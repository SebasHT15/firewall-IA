import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import os

# ── Configuración ──────────────────────────────────────────────
BASE_MODEL  = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
ADAPTER_DIR = os.path.expanduser("~/ai-firewall/model-output")

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>."
)

# ── Casos de prueba ────────────────────────────────────────────
TEST_CASES = [
    # Ataques SQL Injection
    "GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: target.com",
    "GET /login?user=admin'-- HTTP/1.1\nHost: target.com",
    "POST /search HTTP/1.1\nHost: target.com\n\nq=1; DROP TABLE users--",
    # Ataques XSS
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1\nHost: target.com",
    # Command Injection
    "GET /api/ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\nHost: target.com",
    # Path Traversal
    "GET /files?path=../../etc/passwd HTTP/1.1\nHost: target.com",
    # Tráfico legítimo
    "GET /api/products?category=electronics&page=1 HTTP/1.1\nHost: shop.com",
    "POST /api/login HTTP/1.1\nHost: app.com\n\n{\"username\":\"alice\",\"password\":\"pass123\"}",
    "GET /index.html HTTP/1.1\nHost: example.com",
    "GET /api/status HTTP/1.1\nHost: monitor.example.com",
]

# ── Cargar modelo ──────────────────────────────────────────────
print("[1/2] Cargando modelo fine-tuneado...")

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

model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model.eval()
print("      Modelo cargado OK\n")

# ── Inferencia ─────────────────────────────────────────────────
def classify(request):
    prompt = (
        f"<|system|>\n{INSTRUCTION}</s>\n"
        f"<|user|>\n{request}</s>\n"
        f"<|assistant|>\n"
    )
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=60,
            temperature=0.1,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # Extraer solo la respuesta del assistant
    if "<|assistant|>" in response:
        answer = response.split("<|assistant|>")[-1].strip()
    else:
        answer = response.split(request)[-1].strip()
    return answer

# ── Correr pruebas ─────────────────────────────────────────────
print("[2/2] Clasificando requests de prueba...\n")
print("=" * 70)

correct = 0
total   = len(TEST_CASES)

for i, request in enumerate(TEST_CASES):
    expected = "BLOCK" if i < 6 else "ALLOW"
    result   = classify(request)
    got      = "BLOCK" if "BLOCK" in result.upper() else "ALLOW"
    status   = "✅" if got == expected else "❌"
    correct += 1 if got == expected else 0

    print(f"{status} [{expected}→{got}] {request[:60]}...")
    print(f"   Respuesta: {result[:100]}")
    print()

print("=" * 70)
print(f"Accuracy: {correct}/{total} ({100*correct//total}%)")
