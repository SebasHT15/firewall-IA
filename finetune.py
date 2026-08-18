"""
firewall-IA — QLoRA fine-tuning of TinyLlama-1.1B-Chat.

Run (production recipe, unchanged from the original):
    python3.12 finetune.py

Run (E1 compatibility smoke test — small subset, few steps, separate output dir):
    python3.12 finetune.py --smoke

The ML stack is installed for python3.12 on this machine, NOT the default python3.

────────────────────────────────────────────────────────────────────────────
PORTED 2026-08-16 (experiment E1) for transformers 5.8.0 / TRL 1.4.0.

The training RECIPE is unchanged. Only the API surface moved:

  TrainingArguments            -> SFTConfig (SFTConfig subclasses TrainingArguments,
                                  so every existing argument keeps working)
  SFTTrainer(dataset_text_field=)  -> SFTConfig(dataset_text_field=)
  SFTTrainer(max_seq_length=512)   -> SFTConfig(max_length=512)   [rename only]
  SFTTrainer(tokenizer=)           -> SFTTrainer(processing_class=)

Unchanged and verified against the installed API: LoRA r/alpha/dropout/target
modules, NF4 quantization, double quantization, optimizer, learning rate,
epochs, scheduler, warmup, batch size, gradient accumulation.
(Mixed-precision mode is the one exception — see PRECISION / D11 below.)

Verified TRL 1.4 defaults that could otherwise have changed the recipe silently:
  packing=False (matches previous behaviour), completion_only_loss=None
  (not applicable to a plain text field), neftune_noise_alpha=None.
  TRL appends EOS to `text` only when it does not already end with EOS —
  format_example() already ends in `</s>`, so nothing is double-appended.

PRECISION — DECISIONS.md D11 (APPROVED 2026-08-17):

    fp16=True                        ->  fp16=False, bf16=True
    bnb_4bit_compute_dtype=float16   ->  bnb_4bit_compute_dtype=bfloat16

  This is NOT a preference. It is structural:

  1. TRL 1.4 casts every trainable (LoRA) parameter to bfloat16 when the base
     model is 4-bit loaded, following the QLoRA paper
     (trl/trainer/sft_trainer.py:1088-1092). There is no flag to disable it.
  2. fp16=True makes transformers/accelerate wrap the step in
     torch.amp.GradScaler.
  3. GradScaler.unscale_ calls _amp_foreach_non_finite_check_and_unscale_,
     whose CUDA kernel is not implemented for BFloat16:

       RuntimeError: "_amp_foreach_non_finite_check_and_unscale_cuda"
                     not implemented for 'BFloat16'

  So fp16 + 4-bit QLoRA cannot run on TRL 1.4.0 at all. bf16 needs no loss
  scaling, so the GradScaler path disappears entirely. The RTX 4090 Laptop
  (Ada, sm_89) supports bf16 natively.

  Run `python3.12 finetune.py --smoke --force-fp16` to reproduce the crash.
  That flag is opt-in only and contradicts D11 by design; it exists so the
  incompatibility stays reproducible.

  D11 also aligns `bnb_4bit_compute_dtype` to bfloat16, matching the QLoRA
  reference configuration. E1 had left it at float16 pending approval.

  D11 is an environment compatibility / numerical consistency decision. It
  must NOT be presented as a measured model-quality improvement — no such
  comparison exists or can be made, because the fp16 path does not run.

CHECKPOINT RETENTION — DECISIONS.md D12 (APPROVED 2026-08-17):
  save_total_limit=2. E1 measured ~300 MB per checkpoint and the production
  schedule would otherwise produce ~49 of them (~14.8 GB before optimizer
  state). save_steps and all other hyperparameters are unchanged.

CUSTOM STOP TOKEN REMOVED — DECISIONS.md D5, experiment E4 (2026-08-17):

  The `###END###` special token, the tokenizer `add_special_tokens` call and
  the `resize_token_embeddings` call are all gone. Termination now uses
  TinyLlama's native EOS.

  Verified on the installed stack: format_example() ends each sequence with a
  literal "</s>", which tokenizes to eos_token_id 2, and TRL 1.4 appends EOS
  only when the text does not already end with it — so exactly one EOS is
  present, not two.

  Why it was removed (measured in E1):
    * `###END###` was unnecessary — native EOS already exists and was already
      present in every training sequence.
    * Resizing the vocabulary made PEFT set `save_embedding_layers=True`
      automatically, persisting the FULL `embed_tokens` and `lm_head` matrices
      into every checkpoint and into the final adapter.
    * The E1 smoke adapter held ~24 MiB of actual LoRA tensors but totalled
      ~298 MB, the balance being ~250 MiB of those two matrices.
    * The token was never configured as a trainable token
      (`modules_to_save=None`, `trainable_token_indices=None`), so those
      matrices carried no trained information.
    * Removing it simplifies the pipeline and supports the future GGUF /
      embedded-deployment objective (D8 item 3, D10).

  NOTE: no latency improvement is claimed. That remains a hypothesis until a
  controlled experiment measures it (D5).

────────────────────────────────────────────────────────────────────────────
"""

import argparse
import os
import time

import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
)
from peft import LoraConfig, TaskType
from trl import SFTConfig, SFTTrainer

# ── Configuración ──────────────────────────────────────────────
MODEL_NAME   = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"

# V4 CLEAN BASELINE (Issue #7). Points at the frozen, leakage-free E2/E3/E4
# dataset — NOT the historical root train.jsonl/eval.jsonl, which retain the
# envelope shortcuts and 26.65% train/eval leakage found in the audit.
# Identity is pinned by datasets/manifest_v4_clean.json; verify the SHA-256
# hashes before training.
TRAIN_FILE = os.path.expanduser("~/Desktop/firewall-IA/datasets/v4_clean/train.jsonl")
EVAL_FILE  = os.path.expanduser("~/Desktop/firewall-IA/datasets/v4_clean/eval.jsonl")
OUTPUT_DIR   = os.path.expanduser("~/Desktop/firewall-IA/model-output-v4-clean")
MAX_SEQ_LEN  = 512

# E1 smoke-test settings. Separate output dir — never touches model-output-v3.
SMOKE_OUTPUT_DIR = os.path.expanduser("~/Desktop/firewall-IA/model-output-e1-smoke")
SMOKE_TRAIN_SIZE = 500
SMOKE_EVAL_SIZE  = 100
SMOKE_MAX_STEPS  = 12
SMOKE_EVAL_STEPS = 6

parser = argparse.ArgumentParser(description="firewall-IA QLoRA fine-tune")
parser.add_argument("--smoke", action="store_true",
                    help="E1 compatibility smoke test: small subset, few steps, separate output dir")
parser.add_argument("--smoke-train-size", type=int, default=SMOKE_TRAIN_SIZE)
parser.add_argument("--smoke-eval-size", type=int, default=SMOKE_EVAL_SIZE)
parser.add_argument("--smoke-max-steps", type=int, default=SMOKE_MAX_STEPS)
parser.add_argument("--force-fp16", action="store_true",
                    help="Reproduce the E1 fp16 incompatibility (see PRECISION note in the docstring). "
                         "Expected to crash in GradScaler.unscale_ under TRL 1.4 + 4-bit.")
args_cli = parser.parse_args()

SMOKE = args_cli.smoke
if SMOKE:
    OUTPUT_DIR = SMOKE_OUTPUT_DIR
    print("=" * 70)
    print("E1 SMOKE MODE — software compatibility test only.")
    print("This is NOT a valid training run and produces NO research results.")
    print(f"Output dir: {OUTPUT_DIR}")
    print("=" * 70)

t_start = time.perf_counter()

# ── Cuantización 4-bit ─────────────────────────────────────────
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,   # D11 — was float16
    bnb_4bit_use_double_quant=True,
)

# ── Cargar modelo y tokenizer ──────────────────────────────────
print("[1/5] Cargando modelo base...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# No custom stop token. Termination is the model's NATIVE EOS (</s>, id 2),
# which format_example() appends to every training sequence. See D5 / E4.
# The tokenizer vocabulary is NOT resized, so PEFT has no reason to force-save
# the full embed_tokens and lm_head matrices into every checkpoint.

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)
model.config.use_cache = False
print("      Modelo cargado OK")
print(f"      4-bit cargado: {getattr(model, 'is_loaded_in_4bit', False)}")
print(f"      quant_method : {getattr(getattr(model.config, 'quantization_config', None), 'quant_method', 'n/a')}")

# ── Configuración LoRA ─────────────────────────────────────────
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
)

# ── Dataset ────────────────────────────────────────────────────
print("[3/5] Cargando dataset...")

def format_example(example):
    text = (
        f"<|system|>\n{example['instruction']}</s>\n"
        f"<|user|>\n{example['input']}</s>\n"
        f"<|assistant|>\n{example['output']}</s>"
    )
    return {"text": text}

train_dataset = load_dataset("json", data_files=TRAIN_FILE, split="train")
eval_dataset  = load_dataset("json", data_files=EVAL_FILE,  split="train")

if SMOKE:
    # Subset only — the on-disk dataset is never modified.
    n_tr = min(args_cli.smoke_train_size, len(train_dataset))
    n_ev = min(args_cli.smoke_eval_size, len(eval_dataset))
    train_dataset = train_dataset.select(range(n_tr))
    eval_dataset  = eval_dataset.select(range(n_ev))
    print(f"      [smoke] subset: train={n_tr}, eval={n_ev}")

train_dataset = train_dataset.map(format_example)
eval_dataset  = eval_dataset.map(format_example)

print(f"      Train: {len(train_dataset)} ejemplos")
print(f"      Eval:  {len(eval_dataset)} ejemplos")

print("\n── Ejemplo formateado ──")
print(train_dataset[0]["text"][:300])
print("...")

# ── Training Arguments (SFTConfig) ─────────────────────────────
print("\n[4/5] Configurando entrenamiento...")
sft_kwargs = dict(
    output_dir=OUTPUT_DIR,
    num_train_epochs=4,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=2,
    gradient_accumulation_steps=8,
    gradient_checkpointing=True,
    eval_strategy="steps",
    eval_steps=200,
    save_strategy="steps",
    save_steps=200,
    logging_steps=50,
    learning_rate=2e-4,
    # PRECISION — DECISIONS.md D11. bf16, not fp16. See the PRECISION note in
    # the module docstring for the diagnosis. --force-fp16 reproduces the
    # original incompatibility for the record; it contradicts D11 by design.
    fp16=args_cli.force_fp16,
    bf16=not args_cli.force_fp16,
    optim="paged_adamw_8bit",
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    report_to="none",
    load_best_model_at_end=True,
    save_total_limit=2,              # D12 — bound checkpoint retention

    # Moved here from SFTTrainer(...) — TRL 1.4 API:
    dataset_text_field="text",
    max_length=MAX_SEQ_LEN,          # was SFTTrainer(max_seq_length=...) — rename only
)

if SMOKE:
    # Smoke-only overrides. Bound the run and tighten checkpoint retention
    # further than D12's production value of 2, so a compatibility test cannot
    # fill the disk. The production recipe above is untouched.
    sft_kwargs.update(
        max_steps=args_cli.smoke_max_steps,
        eval_steps=SMOKE_EVAL_STEPS,
        save_steps=SMOKE_EVAL_STEPS,
        logging_steps=2,
        save_total_limit=1,
        warmup_ratio=0.0,
    )

training_args = SFTConfig(**sft_kwargs)

# ── Trainer ────────────────────────────────────────────────────
trainer = SFTTrainer(
    model=model,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    peft_config=lora_config,
    processing_class=tokenizer,      # was tokenizer= — renamed in transformers 5.x
    args=training_args,
)

# ── Verificación QLoRA (E1) ────────────────────────────────────
trainable = [(n, p) for n, p in trainer.model.named_parameters() if p.requires_grad]
n_trainable = sum(p.numel() for _, p in trainable)
n_total = sum(p.numel() for p in trainer.model.parameters())
print(f"      Parámetros entrenables: {n_trainable:,} / {n_total:,} "
      f"({100 * n_trainable / max(1, n_total):.4f}%)")
print(f"      Módulos LoRA entrenables: {sum(1 for n, _ in trainable if 'lora' in n.lower())}")
if trainable:
    print(f"      dtype de parámetros entrenables: {sorted({str(p.dtype) for _, p in trainable})}")

# ── Entrenar ───────────────────────────────────────────────────
print("[5/5] Iniciando entrenamiento...")
if torch.cuda.is_available():
    torch.cuda.reset_peak_memory_stats()

train_result = trainer.train(resume_from_checkpoint=False)

# ── Evaluación explícita ───────────────────────────────────────
print("\nEvaluando...")
eval_metrics = trainer.evaluate()
print(f"   eval metrics: {eval_metrics}")

# ── Guardar modelo final ───────────────────────────────────────
print("\n✅ Entrenamiento completo. Guardando modelo...")
trainer.model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"   Modelo guardado en: {OUTPUT_DIR}")

elapsed = time.perf_counter() - t_start
print(f"\n   Duración total: {elapsed:.1f}s ({elapsed/60:.1f} min)")
if torch.cuda.is_available():
    print(f"   Pico de memoria GPU asignada: "
          f"{torch.cuda.max_memory_allocated() / 1024**3:.2f} GiB")
    print(f"   Pico reservado por el caché  : "
          f"{torch.cuda.max_memory_reserved() / 1024**3:.2f} GiB")

if SMOKE:
    print("\n" + "=" * 70)
    print("E1 SMOKE MODE COMPLETE — compatibility only.")
    print("Do NOT interpret the loss values above as research results.")
    print("=" * 70)
