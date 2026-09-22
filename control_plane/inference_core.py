"""
firewall-IA — shared V4 inference core.

Single owner of the runtime inference pipeline: the decision contract, the
prompt template, model loading, generation and parsing. Both the evaluation
harness (`test_model.py`) and the FastAPI control plane (`classifier_api.py`)
import from here, so a request can never be prompted, generated or parsed two
different ways.

Extracted verbatim from `test_model.py` (Issue #15). The prompt template, the
generation parameters and `EXTRACT_RE` are the ones under which the V4-clean
baseline recorded in `reports/v4_clean_eval.json` was measured. Changing any of
them invalidates that baseline — do not, without an experiment.

Dependency direction (must stay acyclic):

    test_model.py  ──►  inference_core  ◄──  classifier_api.py

`inference_core` imports nothing from this project: no dataset generation, no
metric scoring, no manifest handling, no CLI.

Issue #9 added `classify_timed()` — the same generation path with a per-stage
timing breakdown and explicit device synchronization. `classify_raw()` delegates
to it, so the benchmark harness measures exactly the pipeline the control plane
serves. Nothing about the model, prompt, generation parameters or parsing
changed.
"""

import os
import re
import time

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# ── Paths ──────────────────────────────────────────────────────────────────
# Resolved relative to this file so the repo is not tied to one user's $HOME.
# This file lives in control_plane/, one level below the repository root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The V4-clean adapter (Issue #7). The historical `model-output-v3` does not
# exist on disk — see CONTEXT.md §3-historical.
DEFAULT_ADAPTER_DIR = os.environ.get(
    "FIREWALL_ADAPTER_DIR", os.path.join(REPO_ROOT, "model-output-v4-clean")
)

# ── Model / contract constants ─────────────────────────────────────────────
BASE_MODEL = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>."
)

# Decision contract: "ALLOW | <reason>" / "BLOCK | <reason>".
# Terminated by native EOS (D5/E4) — no custom stop token.
# Defensive against leading/trailing whitespace, a trailing period, and any
# continuation text the model emits after the reason.
EXTRACT_RE = re.compile(r"\b(ALLOW|BLOCK)\b\s*\|\s*(.+?)\s*(?:\.|\n|$)")

# Safety bound on generation, not a target length. V4 generations terminate on
# native EOS well before it (mean 11.58 new tokens, P95 13).
MAX_NEW_TOKENS = 40


# ── Prompt ─────────────────────────────────────────────────────────────────
def build_prompt(request):
    """Render one raw HTTP request into the V4 training prompt.

    Identical to `finetune.py:format_example()` minus the trailing
    `{output}</s>` that the model is asked to produce. `request` is RAW HTTP
    TEXT, never structured fields (D1).
    """
    return (f"<|system|>\n{INSTRUCTION}</s>\n"
            f"<|user|>\n{request}</s>\n"
            f"<|assistant|>\n")


# ── Prediction parsing ─────────────────────────────────────────────────────
def parse_prediction(text):
    """Parse raw decoder output into (decision, reason, status).

    POLICY (frozen): extract the FIRST valid ALLOW/BLOCK decision using the E4
    contract regex. If no decision can be extracted, the result is INVALID —
    it is NOT coerced into a decision. Invalid outputs are counted explicitly
    and reported separately (see score_binary).

    status is "ok" or "invalid".
    """
    if text is None:
        return None, None, "invalid"
    m = EXTRACT_RE.search(text)
    if not m:
        return None, None, "invalid"
    return m.group(1).upper(), m.group(2).strip(), "ok"


def normalize_reason(reason):
    """Canonical form for reason comparison.

    Objective normalisation only — casefold, collapse whitespace, strip a
    single trailing period. NO synonym table, NO keyword heuristics, NO
    subjective mapping. A predicted reason either matches a canonical dataset
    reason exactly under this normalisation, or it does not.
    """
    if reason is None:
        return ""
    return re.sub(r"\s+", " ", reason.strip().casefold()).rstrip(".").strip()


# ── Model ──────────────────────────────────────────────────────────────────
def resolve_device():
    """Device string used for tensor placement. CUDA when available."""
    return "cuda" if torch.cuda.is_available() else "cpu"


def load_model(adapter_dir=DEFAULT_ADAPTER_DIR):
    """Load base TinyLlama + LoRA adapter. No tokenizer resize, no custom stop
    token (removed in E4 / D5).

    The quantization config is the RUNTIME one under which the V4 baseline was
    measured: 4-bit nf4 with a bfloat16 compute dtype and no double
    quantization. `finetune.py` additionally sets
    `bnb_4bit_use_double_quant=True`; that is a TRAINING setting and is
    deliberately not mirrored here — training and inference configs do not have
    to be identical, and changing this one would invalidate the baseline.
    """
    print(f"Loading model from {adapter_dir} ...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    tok = AutoTokenizer.from_pretrained(adapter_dir)
    tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, quantization_config=bnb_config, device_map="auto")
    mdl = PeftModel.from_pretrained(base, adapter_dir)
    mdl.eval()
    return tok, mdl


def device_sync(device):
    """Block until every operation queued on `device` has actually finished.

    CUDA kernel launches are asynchronous: control returns to Python as soon as
    the work is *submitted*, not when it is done. A stopwatch stopped without
    this would time submission, not inference. No-op on CPU, where execution is
    already synchronous, and no-op if CUDA is not available.
    """
    if torch.cuda.is_available() and str(device).startswith("cuda"):
        torch.cuda.synchronize(device)


def classify_timed(tok, mdl, request, device, max_new_tokens=MAX_NEW_TOKENS):
    """Generate one decision with a per-stage timing breakdown (Issue #9).

    Returns `(raw_decoded_text, measure)`. `measure` is a flat dict; every key
    ending in `_ms` is a duration in milliseconds, the rest are counters:

        prompt_build_ms   render the V4 prompt template
        tokenize_ms       tokenizer call, CPU tensors
        transfer_ms       host -> device copy
        generate_ms       generate(), synchronized     <- Issue #9 PRIMARY SCOPE
        decode_ms         detokenize the new tokens
        prompt_tokens     input_ids length fed to generate()
        generated_tokens  new tokens produced
        stopped_on_eos    True if generation ended on native EOS rather than
                          hitting the max_new_tokens safety bound

    `generate_ms` is bracketed by `device_sync()` on both sides, so it contains
    the whole generation and nothing queued before it. It is model-side
    inference only — NOT end-to-end gateway latency (Issue #18). The D36
    objective covers the whole pipeline timed here (prompt_build_ms through
    decode_ms, plus parsing), not generate_ms alone.

    This is the single implementation of the V4 generation path;
    `classify_raw()` delegates to it, so instrumentation cannot drift from what
    the control plane actually runs.
    """
    t0 = time.perf_counter()
    prompt = build_prompt(request)
    t1 = time.perf_counter()
    cpu_inputs = tok(prompt, return_tensors="pt")
    t2 = time.perf_counter()
    inputs = cpu_inputs.to(device)
    device_sync(device)
    t3 = time.perf_counter()

    with torch.no_grad():
        out = mdl.generate(**inputs, max_new_tokens=max_new_tokens,
                           do_sample=False, pad_token_id=tok.eos_token_id)
    device_sync(device)
    t4 = time.perf_counter()

    prompt_len = inputs["input_ids"].shape[1]
    new = out[0][prompt_len:]
    text = tok.decode(new, skip_special_tokens=True)
    t5 = time.perf_counter()

    n_new = int(new.shape[0])
    return text, {
        "prompt_build_ms": (t1 - t0) * 1000,
        "tokenize_ms": (t2 - t1) * 1000,
        "transfer_ms": (t3 - t2) * 1000,
        "generate_ms": (t4 - t3) * 1000,
        "decode_ms": (t5 - t4) * 1000,
        "prompt_tokens": int(prompt_len),
        "generated_tokens": n_new,
        "stopped_on_eos": bool(n_new < max_new_tokens),
    }


def classify_raw(tok, mdl, request, device, max_new_tokens=MAX_NEW_TOKENS):
    """Generate one decision. Returns (raw_decoded_text, model_latency_ms).

    Greedy (`do_sample=False`), so the same request yields the same output.
    Generation stops on the model's native EOS; `max_new_tokens` is only a
    safety bound.

    The returned latency covers `generate()` alone — model-side inference, NOT
    end-to-end gateway latency, and not the full inference pipeline that the
    D36 objective covers.

    METHODOLOGY CHANGE (Issue #9, D31): generation is now bracketed by
    `device_sync()`, so this timer measures completed GPU work instead of
    submitted work. It is a stopwatch correction, not a change to the model,
    the prompt, the parameters or the output — the decision returned for a
    given request is bit-identical to before. Latency figures measured under
    the older unsynchronized timer (the 270.8 ms P95 in
    `reports/v4_clean_eval.json`) are therefore historical antecedents, not
    `baseline-local-v1` results.
    """
    text, m = classify_timed(tok, mdl, request, device, max_new_tokens)
    return text, m["generate_ms"]
