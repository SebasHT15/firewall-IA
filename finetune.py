import os
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer

# ── Configuración ──────────────────────────────────────────────
MODEL_NAME   = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
TRAIN_FILE   = os.path.expanduser("~/ai-firewall/train.jsonl")
EVAL_FILE    = os.path.expanduser("~/ai-firewall/eval.jsonl")
OUTPUT_DIR   = os.path.expanduser("~/ai-firewall/model-output")
MAX_SEQ_LEN  = 512

# ── Cuantización 4-bit ─────────────────────────────────────────
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)

# ── Cargar modelo y tokenizer ──────────────────────────────────
print("[1/5] Cargando modelo base...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# Agregar stop token ###END###
tokenizer.add_special_tokens({"additional_special_tokens": ["###END###"]})

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)
model.resize_token_embeddings(len(tokenizer))
model.config.use_cache = False
print("      Modelo cargado OK")

# ── Configuración LoRA ─────────────────────────────────────────
print("[2/5] Aplicando LoRA...")
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

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

train_dataset = train_dataset.map(format_example)
eval_dataset  = eval_dataset.map(format_example)

print(f"      Train: {len(train_dataset)} ejemplos")
print(f"      Eval:  {len(eval_dataset)} ejemplos")

print("\n── Ejemplo formateado ──")
print(train_dataset[0]["text"][:300])
print("...")

# ── Training Arguments ─────────────────────────────────────────
print("\n[4/5] Configurando entrenamiento...")
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    gradient_accumulation_steps=4,
    evaluation_strategy="steps",
    eval_steps=200,
    save_steps=200,
    logging_steps=50,
    learning_rate=2e-4,
    fp16=True,
    optim="paged_adamw_8bit",
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    report_to="none",
    load_best_model_at_end=True,
)

# ── Trainer ────────────────────────────────────────────────────
trainer = SFTTrainer(
    model=model,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    peft_config=lora_config,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LEN,
    tokenizer=tokenizer,
    args=training_args,
)

# ── Entrenar ───────────────────────────────────────────────────
print("[5/5] Iniciando entrenamiento...")
trainer.train()

# ── Guardar modelo final ───────────────────────────────────────
print("\n✅ Entrenamiento completo. Guardando modelo...")
trainer.model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"   Modelo guardado en: {OUTPUT_DIR}")
