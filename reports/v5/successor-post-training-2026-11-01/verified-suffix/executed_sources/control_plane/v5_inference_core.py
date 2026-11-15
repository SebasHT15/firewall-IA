"""
firewall-IA — shared V5 inference core (hybrid cascade, semantic stage).

Single owner of the V5 runtime pipeline: the ratified recipe (template,
vocabulary, token budget), model loading, template-safe encoding, bounded
greedy generation and the strict output parser. The V5 service
(`v5_classifier_api.py`) and the cascade evaluation harness both import from
here, so a request can never be prompted, generated or parsed two different
ways — the V5 analogue of `inference_core` for V4.

Unlike V4 (`inference_core.build_prompt` + `EXTRACT_RE`), V5 is bound to the
D71-ratified contract and reuses the exact modules the generator and trainer
used:

    control_plane/v5_tokenization.encode_prompt      (template-safe ids, spec 5.4)
    control_plane/v5_output_contract.parse_v5_output (strict: exact vocab + EOS)
    scripts/training/v5_train_data                   (recipe -> template, vocab, contract)

The input is the CANONICAL REQUEST text (`canonical_request.CanonicalResult.text`),
the same representation Model 2 scores and the generator trained on — NOT V4's D1
render and NOT raw wire bytes. An output that is not exactly one vocabulary string
terminated by native EOS is `invalid`; it is never coerced into a decision and in
particular never into an ALLOW (D4/D25/D34). The data plane enforces fail-closed.

Heavy ML imports (torch/transformers/peft) are deferred into `load_v5()` so this
module can be imported for its contract metadata (fingerprint, budget, vocabulary)
in the data-plane environment, which has no ML stack.

Dependency direction (acyclic): v5_classifier_api ─► v5_inference_core ◄─ cascade eval.
`v5_inference_core` imports no gateway, no dataset build, no metric scoring.
"""

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (HERE, os.path.join(REPO_ROOT, "scripts", "training")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_output_contract as OC  # noqa: E402
import v5_tokenization as T  # noqa: E402
import v5_train_data as D  # noqa: E402  (recipe helpers; also puts control_plane/ on sys.path)

# ── Paths / recipe (single source of truth) ─────────────────────────────────
DEFAULT_RECIPE = os.environ.get(
    "FIREWALL_V5_RECIPE",
    os.path.join(REPO_ROOT, "scripts", "training", "v5_training_recipe_v1.json"),
)
# The FINAL adapter directory. Overridable like V4's FIREWALL_ADAPTER_DIR, but V5
# serving requires its OWN variable: changing V4's FIREWALL_ADAPTER_DIR does not
# make this service serve V5 (different template, tokenizer handling and parser).
DEFAULT_ADAPTER_DIR = os.environ.get(
    "FIREWALL_V5_ADAPTER_DIR",
    os.path.join(REPO_ROOT, "model-output-v5", "final",
                 "v5-final-v4-20261027T022649Z", "adapter"),
)


class V5ContractError(ValueError):
    """The loaded adapter/recipe does not satisfy the ratified V5 contract."""


class V5ContentRejected(ValueError):
    """Content cannot be encoded under the V5 contract (special ids or over budget).

    A protocol-level reject at the V5 boundary, never an ALLOW. The canonical
    stage normally prevents this (size is checked against B there); this guards
    the case where V5 is called on text that was not size-checked for V5."""


@dataclass(frozen=True)
class V5Contract:
    """Everything derived from the ratified recipe, with no model loaded."""
    recipe_path: str
    recipe_sha256: str
    template: object            # v5_tokenization.PromptTemplate
    vocabulary: tuple
    template_fingerprint: str
    base_model: str
    base_revision: str
    max_length: int
    token_budget_B: int
    label_budget: int
    overhead: int
    margin: int
    max_new_tokens: int
    bos_id: Optional[int] = None
    eos_id: Optional[int] = None


def load_contract(recipe_path: str = DEFAULT_RECIPE) -> V5Contract:
    """Build the recipe-derived contract WITHOUT loading the model or tokenizer.

    `label_budget`/`overhead`/`bos_id`/`eos_id` are left from the recipe's own
    token_budget record; the tokenizer-measured values are filled by `load_v5`
    and cross-checked there. `max_new_tokens = label_budget + 4` is the exact
    generation bound the generator used (`finetune_v5.py`)."""
    recipe, recipe_sha = D.load_recipe(recipe_path)
    template = D.recipe_template(recipe)
    vocab = D.recipe_vocabulary(recipe)
    fp = D.template_fingerprint(recipe)
    tb = recipe["token_budget"]
    label_budget = tb.get("label_budget")
    overhead = tb.get("overhead")
    return V5Contract(
        recipe_path=recipe_path,
        recipe_sha256=recipe_sha,
        template=template,
        vocabulary=tuple(vocab),
        template_fingerprint=fp,
        base_model=recipe["base_model"]["name"],
        base_revision=recipe["base_model"]["revision"],
        max_length=tb["max_length"],
        token_budget_B=tb["B"],
        label_budget=label_budget if isinstance(label_budget, int) else 13,
        overhead=overhead if isinstance(overhead, int) else 76,
        margin=tb["margin"],
        max_new_tokens=(label_budget if isinstance(label_budget, int) else 13) + 4,
    )


def adapter_fingerprint(adapter_dir: str) -> str:
    """sha256 over the adapter weights file, for the readiness/identity record."""
    path = os.path.join(adapter_dir, "adapter_model.safetensors")
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Model loading (defers torch/transformers/peft) ──────────────────────────
def resolve_device():
    import torch
    return "cuda" if torch.cuda.is_available() else "cpu"


def device_sync(device):
    import torch
    if torch.cuda.is_available() and str(device).startswith("cuda"):
        torch.cuda.synchronize(device)


@dataclass
class V5Model:
    tokenizer: object
    model: object
    contract: V5Contract
    device: str
    adapter_dir: str
    adapter_sha256: str
    runtime_profile: object = None
    runtime_settings: object = None
    decoder: object = None
    decoder_candidates: object = None


def load_v5(adapter_dir: str = DEFAULT_ADAPTER_DIR,
            recipe_path: str = DEFAULT_RECIPE,
            *, expected_fingerprint: Optional[str] = None,
            runtime_profile_path: Optional[str] = None,
            runtime_profile_sha256: Optional[str] = None,
            allow_experimental_runtime: bool = False) -> V5Model:
    """Load the pinned base and adapter, binding the measured token contract.

    Defaults reproduce recipe NF4 + double quantization. A separately hashed
    runtime profile can select NF4 without double quantization or BF16. Profiles
    bind the recipe and adapter and require explicit opt-in while experimental;
    they never amend the training recipe or its approval state.

    Raises V5ContractError if the recipe fingerprint, the measured token budget
    or the tokenizer specials do not match the recipe, or if
    `expected_fingerprint` is given and differs.
    """
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    recipe, recipe_sha256 = D.load_recipe(recipe_path)
    contract = load_contract(recipe_path)
    if recipe_sha256 != contract.recipe_sha256:
        raise V5ContractError("recipe changed while loading the contract")
    if expected_fingerprint is not None and contract.template_fingerprint != expected_fingerprint:
        raise V5ContractError(
            f"template fingerprint {contract.template_fingerprint} != expected {expected_fingerprint}")

    weights_sha256 = adapter_fingerprint(adapter_dir)
    runtime_profile = None
    decoder = None
    if runtime_profile_path is not None:
        from v5_runtime_profile import load_profile
        runtime_profile = load_profile(
            runtime_profile_path, expected_sha256=runtime_profile_sha256,
            recipe_sha256=contract.recipe_sha256, adapter_sha256=weights_sha256,
            allow_experimental=allow_experimental_runtime)
        from v5_runtime_profile import load_decoder
        decoder = load_decoder(runtime_profile)
    elif runtime_profile_sha256 is not None:
        raise V5ContractError("runtime profile hash supplied without profile path")
    q = recipe["quantization"]
    load_options = {}
    if runtime_profile is not None and runtime_profile.precision == "bf16":
        load_options["dtype"] = torch.bfloat16
    else:
        load_options["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=(True if runtime_profile else bool(q.get("load_in_4bit", True))),
            bnb_4bit_quant_type=("nf4" if runtime_profile else q.get("bnb_4bit_quant_type", "nf4")),
            bnb_4bit_use_double_quant=(runtime_profile.double_quant if runtime_profile
                                      else bool(q.get("bnb_4bit_use_double_quant", True))),
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
    tok = AutoTokenizer.from_pretrained(adapter_dir)
    tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        contract.base_model, revision=contract.base_revision,
        device_map="auto", local_files_only=True, **load_options)
    mdl = PeftModel.from_pretrained(base, adapter_dir)
    mdl.eval()
    if adapter_fingerprint(adapter_dir) != weights_sha256:
        raise V5ContractError("adapter weights changed while loading")

    # Re-measure the token contract with the loaded tokenizer and fail if the
    # recipe's recorded values do not reproduce (spec §5.5).
    measured, diags = D.measure_contract(tok, recipe)
    if diags:
        raise V5ContractError(f"token contract diagnostics: {[d.code for d in diags]}")
    # The recipe pins B (and max_length, margin); overhead and label_budget are
    # tokenizer-measured. Enforce the recipe's B against what the tokenizer yields
    # (measured.B is the ceiling max_length - overhead - label - margin); a recipe
    # B above that ceiling would already be a diagnostic above.
    if contract.token_budget_B > measured.template_max_B:
        raise V5ContractError(
            f"recipe B={contract.token_budget_B} exceeds tokenizer ceiling {measured.template_max_B}")
    contract = V5Contract(
        **{**contract.__dict__,
           "bos_id": tok.bos_token_id, "eos_id": tok.eos_token_id,
           "label_budget": measured.label_budget, "overhead": measured.overhead,
           "max_new_tokens": measured.label_budget + 4})
    device = resolve_device()
    base_config = mdl.get_base_model().config
    actual_quant = getattr(base_config, "quantization_config", None)
    if actual_quant is not None and hasattr(actual_quant, "to_dict"):
        actual_quant = actual_quant.to_dict()
    actual_quant = actual_quant or {}
    runtime_settings = {
        "loaded_in_4bit": bool(getattr(mdl, "is_loaded_in_4bit", False)),
        "double_quant": actual_quant.get("bnb_4bit_use_double_quant"),
        "model_dtype": str(mdl.dtype),
        "attention_implementation": getattr(base_config, "_attn_implementation", None),
        "profile_id": runtime_profile.profile_id if runtime_profile else None,
    }
    if decoder is not None:
        runtime_settings.update(decoder=runtime_profile.decoder,
                                decoder_sha256=runtime_profile.decoder_sha256)
    loaded = V5Model(tokenizer=tok, model=mdl, contract=contract, device=device,
                   adapter_dir=adapter_dir, adapter_sha256=weights_sha256,
                   runtime_profile=runtime_profile, runtime_settings=runtime_settings,decoder=decoder)
    if decoder is not None:
        loaded.decoder_candidates = decoder.candidates_for(loaded)
    return loaded


# ── Encoding / generation / parsing ─────────────────────────────────────────
def encode_canonical(contract: V5Contract, tok, canonical_text: str):
    """Template-safe ids for one canonical-request text.

    Raises V5ContentRejected if the content yields a special/added id or exceeds
    the token budget B — the encoder NEVER truncates (spec §5.4/§5.5)."""
    try:
        T.check_content_has_no_special_ids(tok, contract.template, canonical_text)
    except ValueError as e:
        raise V5ContentRejected(f"content special/added ids: {e}") from None
    ids = T.encode_prompt(tok, contract.template, canonical_text)
    content_tokens = len(ids) - contract.overhead
    if content_tokens > contract.token_budget_B:
        raise V5ContentRejected(
            f"{content_tokens} content tokens > B={contract.token_budget_B}")
    return ids


def classify_canonical(m: V5Model, canonical_text: str):
    """Classify one canonical-request text. Returns (ParsedOutput, measure).

    `measure` is a flat dict; keys ending in `_ms` are milliseconds, the rest
    counters. Greedy, so deterministic. Generation is bounded by
    `contract.max_new_tokens` and stops on native EOS; a generation that hits the
    bound has `ended_with_eos=False` and parses `invalid` (no_eos), never ALLOW.

    On V5ContentRejected the result is an `invalid` ParsedOutput with
    invalid_reason `content_rejected` and no generation is run — a fail-closed
    protocol reject at the V5 boundary.
    """
    if m.decoder is not None:
        return m.decoder.classify_verified(m,canonical_text,m.decoder_candidates)
    import torch
    tok, mdl, contract, device = m.tokenizer, m.model, m.contract, m.device
    t0 = time.perf_counter()
    try:
        ids = encode_canonical(contract, tok, canonical_text)
    except V5ContentRejected as e:
        parsed = OC.ParsedOutput(OC.INVALID, None, None, "content_rejected")
        return parsed, {"encode_ms": (time.perf_counter() - t0) * 1000,
                        "tokenize_ms": 0.0, "transfer_ms": 0.0, "generate_ms": 0.0,
                        "decode_ms": 0.0, "parse_ms": 0.0, "prompt_tokens": 0,
                        "generated_tokens": 0, "ended_with_eos": False,
                        "content_rejected": str(e)}
    t1 = time.perf_counter()
    x = torch.tensor([ids], device=device)
    attn = torch.ones_like(x)
    device_sync(device)
    t2 = time.perf_counter()
    with torch.no_grad():
        out = mdl.generate(input_ids=x, attention_mask=attn, do_sample=False,
                           max_new_tokens=contract.max_new_tokens,
                           eos_token_id=tok.eos_token_id, pad_token_id=tok.eos_token_id)
    device_sync(device)
    t3 = time.perf_counter()
    prompt_len = x.shape[1]
    new = out[0][prompt_len:]
    n_new = int(new.shape[0])
    new_list = new.tolist()
    ended = bool(n_new > 0 and tok.eos_token_id in new_list)
    text = tok.decode(new, skip_special_tokens=True)
    t4 = time.perf_counter()
    parsed = OC.parse_v5_output(text, contract.vocabulary, ended_with_eos=ended)
    t5 = time.perf_counter()
    return parsed, {
        "encode_ms": (t1 - t0) * 1000,
        "tokenize_ms": 0.0,
        "transfer_ms": (t2 - t1) * 1000,
        "generate_ms": (t3 - t2) * 1000,
        "decode_ms": (t4 - t3) * 1000,
        "parse_ms": (t5 - t4) * 1000,
        "prompt_tokens": int(prompt_len),
        "generated_tokens": n_new,
        "ended_with_eos": ended,
        "raw_text": text,
    }


def contract_summary(contract: V5Contract) -> dict:
    """JSON-safe identity record for logs / readiness / evaluation metadata."""
    return {
        "recipe_path": os.path.relpath(contract.recipe_path, REPO_ROOT),
        "recipe_sha256": contract.recipe_sha256,
        "template_fingerprint": contract.template_fingerprint,
        "base_model": contract.base_model,
        "base_revision": contract.base_revision,
        "vocabulary": list(contract.vocabulary),
        "max_length": contract.max_length,
        "token_budget_B": contract.token_budget_B,
        "label_budget": contract.label_budget,
        "overhead": contract.overhead,
        "margin": contract.margin,
        "max_new_tokens": contract.max_new_tokens,
        "bos_id": contract.bos_id,
        "eos_id": contract.eos_id,
    }
