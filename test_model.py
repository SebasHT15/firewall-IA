import torch
import re
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import os

# ── Configuración ──────────────────────────────────────────────
BASE_MODEL  = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
ADAPTER_DIR = os.path.expanduser("~/Desktop/firewall-IA/model-output-v2")

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>. Then output ###END###"
)

# ── Casos de prueba ────────────────────────────────────────────
# BLOCK cases: indices 0-21 (22 total)
# ALLOW cases: indices 22-25 (4 total)
TEST_CASES = [
    # ── SQL Injection (original) ───────────────────────────────
    "GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: target.com",
    "GET /login?user=admin'-- HTTP/1.1\nHost: target.com",
    "POST /search HTTP/1.1\nHost: target.com\n\nq=1; DROP TABLE users--",
    # ── XSS Injection (original) ──────────────────────────────
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1\nHost: target.com",
    # ── Command Injection (original) ──────────────────────────
    "GET /api/ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\nHost: target.com",
    # ── Path Traversal (original) ─────────────────────────────
    "GET /files?path=../../etc/passwd HTTP/1.1\nHost: target.com",
    # ── SSRF ──────────────────────────────────────────────────
    "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: target.com",
    "POST /api/proxy HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nurl=http://internal.corp.local/admin",
    # ── JWT Attacks ───────────────────────────────────────────
    "GET /api/admin HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
    "GET /api/profile HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.forged_signature",
    # ── GraphQL Injection ─────────────────────────────────────
    "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"{ __schema { types { name fields { name } } } }\"}",
    "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"{ user(id: \\\"1 UNION SELECT username,password FROM users--\\\") { id name email } }\"}",
    # ── NoSQL Injection ───────────────────────────────────────
    "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
    "GET /api/users?filter={\"$where\":\"this.role=='admin'\"} HTTP/1.1\nHost: target.com",
    # ── Server Side Template Injection ────────────────────────
    "GET /greet?name={{7*7}} HTTP/1.1\nHost: target.com",
    "POST /render HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\ntemplate={{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    # ── File Inclusion ────────────────────────────────────────
    "GET /index.php?lang=../../../../etc/passwd HTTP/1.1\nHost: target.com",
    "GET /page.php?file=php://filter/convert.base64-encode/resource=config HTTP/1.1\nHost: target.com",
    # ── Insecure Deserialization ──────────────────────────────
    "POST /api/session HTTP/1.1\nHost: target.com\nContent-Type: application/x-java-serialized-object\n\nrO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
    "POST /api/data HTTP/1.1\nHost: target.com\nContent-Type: application/octet-stream\n\nO:8:\"stdClass\":1:{s:4:\"exec\";s:9:\"id>/tmp/x\";}",
    # ── HTTP Request Smuggling ────────────────────────────────
    "POST /api/data HTTP/1.1\nHost: target.com\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\r\n\r\nGET /admin HTTP/1.1\nHost: target.com",
    "POST / HTTP/1.1\nHost: target.com\nContent-Length: 44\nTransfer-Encoding: chunked\n\nb\r\nsmuggled=yes\r\n0\r\n\r\nGET /internal HTTP/1.1",
    # ── Tráfico legítimo (original) ───────────────────────────
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
base_model.resize_token_embeddings(len(tokenizer))

model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model.eval()
print("      Modelo cargado OK\n")

device = "cuda" if torch.cuda.is_available() else "cpu"
end_token_id = tokenizer.convert_tokens_to_ids("###END###")

# ── Inferencia ─────────────────────────────────────────────────
def classify(request):
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
    # Decodificar solo los tokens nuevos (no el prompt)
    input_len = inputs["input_ids"].shape[1]
    new_tokens = outputs[0][input_len:]
    response = tokenizer.decode(new_tokens, skip_special_tokens=True)

    # Extraer solo ALLOW/BLOCK | <razón> usando regex
    match = re.search(r"(ALLOW|BLOCK)\s*\|\s*(.+?)(?:\s*###END###|\.|$)", response)
    if match:
        return f"{match.group(1)} | {match.group(2).strip()}"
    # Fallback: retornar primera línea limpia
    return response.split("\n")[0].strip()

# ── Correr pruebas ─────────────────────────────────────────────
print("[2/2] Clasificando requests de prueba...\n")
print("=" * 70)

correct = 0
total   = len(TEST_CASES)

for i, request in enumerate(TEST_CASES):
    expected = "BLOCK" if i < 22 else "ALLOW"
    result   = classify(request)
    got      = "BLOCK" if "BLOCK" in result.upper() else "ALLOW"
    status   = "✅" if got == expected else "❌"
    correct += 1 if got == expected else 0

    print(f"{status} [{expected}→{got}] {request[:60]}...")
    print(f"   Respuesta: {result}")
    print()

print("=" * 70)
print(f"Accuracy: {correct}/{total} ({100*correct//total}%)")

# ── Suite adversarial ──────────────────────────────────────────
# Casos que el modelo NO vio en entrenamiento:
#   - Ataques conocidos con ofuscación (URL-encoded, unicode, IFS)
#   - Categorías fuera de las 14 entrenadas (CRLF, HPP, XPath)
#   - Falsos positivos: tráfico legítimo con palabras clave sospechosas
#
# expected: (request, "BLOCK"|"ALLOW", descripción)
ADVERSARIAL_CASES = [
    # ── Obfuscated known attacks ───────────────────────────────
    (
        "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: target.com",
        "BLOCK",
        "SQL injection, URL-encoded",
    ),
    (
        "GET /search?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e HTTP/1.1\nHost: target.com",
        "BLOCK",
        "XSS, unicode-escaped",
    ),
    (
        "GET /api/ping?host=127.0.0.1;$(whoami) HTTP/1.1\nHost: target.com",
        "BLOCK",
        "Command injection, bash substitution",
    ),
    (
        "GET /api/ping?host=127.0.0.1|$(cat${IFS}/etc/passwd) HTTP/1.1\nHost: target.com",
        "BLOCK",
        "Command injection, IFS evasion",
    ),
    # ── Attack categories outside the 14 trained ──────────────
    (
        "GET /redirect?url=https://evil.com%0d%0aSet-Cookie:%20session=hijacked HTTP/1.1\nHost: target.com",
        "BLOCK",
        "CRLF injection",
    ),
    (
        "GET /search?id=1&id=2&id=99999 HTTP/1.1\nHost: target.com",
        "BLOCK",
        "HTTP Parameter Pollution",
    ),
    (
        "POST /xml HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<user><name>' or '1'='1</name></user>",
        "BLOCK",
        "XPath injection",
    ),
    (
        "GET /api/user?input={{''.__class__.__mro__[1].__subclasses__()}} HTTP/1.1\nHost: target.com",
        "BLOCK",
        "Python SSTI advanced",
    ),
    # ── Potential false positives ──────────────────────────────
    (
        "GET /ui/dropdown?action=drop&item=table HTTP/1.1\nHost: app.com",
        "ALLOW",
        "Legitimate UI action, contains 'drop table' keywords",
    ),
    (
        "POST /api/users HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"role\":\"admin\",\"active\":true,\"username\":\"bob\"}",
        "ALLOW",
        "Legitimate admin API call",
    ),
    (
        "GET /blog/post?title=how-to-union-workers-rights HTTP/1.1\nHost: blog.example.com",
        "ALLOW",
        "Legitimate blog URL, contains 'union'",
    ),
    (
        "GET /api/search?q=select+your+plan HTTP/1.1\nHost: app.com",
        "ALLOW",
        "Legitimate search query, contains 'select'",
    ),
]

print()
print("=" * 70)
print("ADVERSARIAL TEST SUITE")
print("=" * 70)

adv_correct = 0
adv_total   = len(ADVERSARIAL_CASES)

for request, expected, description in ADVERSARIAL_CASES:
    result  = classify(request)
    got     = "BLOCK" if "BLOCK" in result.upper() else "ALLOW"
    status  = "✅" if got == expected else "❌"
    adv_correct += 1 if got == expected else 0

    print(f"{status} [{expected}→{got}] {description}")
    print(f"   Request:  {request[:70]}...")
    print(f"   Respuesta: {result}")
    print()

print("=" * 70)
print(f"Adversarial Accuracy: {adv_correct}/{adv_total} ({100*adv_correct//adv_total}%)")
