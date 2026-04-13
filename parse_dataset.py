import os
import re
import json
import random

# ── Configuración ──────────────────────────────────────────────
PAYLOADS_REPO   = os.path.expanduser("~/PayloadsAllTheThings")
OUTPUT_TRAIN    = os.path.expanduser("~/ai-firewall/train.jsonl")
OUTPUT_EVAL     = os.path.expanduser("~/ai-firewall/eval.jsonl")
EVAL_SPLIT      = 0.2
RANDOM_SEED     = 42

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>. Then output ###END###"
)

# ── Categorías a parsear ────────────────────────────────────────
CATEGORIES = {
    "SQL Injection":    "BLOCK | SQL injection payload detected.",
    "XSS Injection":    "BLOCK | Cross-site scripting payload detected.",
    "Path Traversal":   "BLOCK | Path traversal attack detected.",
    "Command Injection":"BLOCK | Command injection payload detected.",
    "LDAP Injection":   "BLOCK | LDAP injection payload detected.",
    "XXE Injection":    "BLOCK | XML external entity injection detected.",
    "CSRF Injection":   "BLOCK | CSRF attack pattern detected.",
    "Open Redirect":    "BLOCK | Open redirect payload detected.",
}

# ── Tráfico legítimo sintético ──────────────────────────────────
LEGIT_REQUESTS = [
    "GET /index.html HTTP/1.1\nHost: example.com",
    "GET /products?category=electronics HTTP/1.1\nHost: shop.com",
    "GET /api/users/123 HTTP/1.1\nHost: api.example.com",
    "POST /api/login HTTP/1.1\nHost: app.com\n\n{\"username\":\"alice\",\"password\":\"secret123\"}",
    "GET /images/logo.png HTTP/1.1\nHost: example.com",
    "GET /search?q=laptop+cheap HTTP/1.1\nHost: store.com",
    "POST /api/orders HTTP/1.1\nHost: shop.com\n\n{\"item\":\"book\",\"qty\":2}",
    "GET /about HTTP/1.1\nHost: company.com",
    "GET /api/products?page=2&limit=10 HTTP/1.1\nHost: api.store.com",
    "POST /contact HTTP/1.1\nHost: example.com\n\n{\"name\":\"Bob\",\"email\":\"bob@mail.com\",\"message\":\"Hello\"}",
    "GET /favicon.ico HTTP/1.1\nHost: example.com",
    "GET /api/weather?city=SanJose HTTP/1.1\nHost: weather.api.com",
    "PUT /api/users/42 HTTP/1.1\nHost: api.example.com\n\n{\"email\":\"new@mail.com\"}",
    "DELETE /api/cart/item/7 HTTP/1.1\nHost: shop.com",
    "GET /docs/setup.html HTTP/1.1\nHost: docs.example.com",
    "GET /api/status HTTP/1.1\nHost: monitor.example.com",
    "POST /api/feedback HTTP/1.1\nHost: app.com\n\n{\"rating\":5,\"comment\":\"Great service\"}",
    "GET /blog/post/how-to-cook-pasta HTTP/1.1\nHost: blog.example.com",
    "GET /api/categories HTTP/1.1\nHost: api.shop.com",
    "GET /robots.txt HTTP/1.1\nHost: example.com",
]

HTTP_METHODS  = ["GET", "POST", "PUT", "DELETE", "PATCH"]
PATHS         = ["/search", "/api/query", "/login", "/api/data", "/filter", "/api/users", "/admin/query"]
PARAMS        = ["id", "q", "user", "input", "data", "filter", "search", "name", "value", "cmd"]

def extract_payloads_from_md(filepath):
    payloads = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', content, re.DOTALL)
        for block in code_blocks:
            for line in block.splitlines():
                line = line.strip()
                if len(line) > 3 and not line.startswith("#"):
                    payloads.append(line)
        for line in content.splitlines():
            line = line.strip()
            if any(p in line for p in ["'", '"', "--", ";", "UNION", "SELECT", "DROP",
                                        "<script", "../", "&&", "||", "|", "$(", "`"]):
                if 10 < len(line) < 300:
                    payloads.append(line)
    except Exception as e:
        print(f"  [WARN] No se pudo leer {filepath}: {e}")
    return list(set(payloads))

def wrap_in_http(payload, label):
    method = random.choice(HTTP_METHODS)
    path   = random.choice(PATHS)
    param  = random.choice(PARAMS)
    if method == "GET":
        request = f"GET {path}?{param}={payload} HTTP/1.1\nHost: target.internal.com"
    else:
        request = f"{method} {path} HTTP/1.1\nHost: target.internal.com\nContent-Type: application/x-www-form-urlencoded\n\n{param}={payload}"
    return {
        "instruction": INSTRUCTION,
        "input": request,
        "output": f"{label} ###END###"
    }

def build_dataset():
    examples = []
    total_block = 0
    for category, label in CATEGORIES.items():
        category_path = os.path.join(PAYLOADS_REPO, category)
        if not os.path.isdir(category_path):
            print(f"  [SKIP] Carpeta no encontrada: {category_path}")
            continue
        print(f"  [+] Procesando: {category}")
        for fname in os.listdir(category_path):
            if fname.endswith(".md"):
                fpath = os.path.join(category_path, fname)
                payloads = extract_payloads_from_md(fpath)
                for p in payloads:
                    examples.append(wrap_in_http(p, label))
                    total_block += 1
        for root, dirs, files in os.walk(category_path):
            for fname in files:
                if fname.endswith(".txt"):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if len(line) > 3:
                                    examples.append(wrap_in_http(line, label))
                                    total_block += 1
                    except Exception as e:
                        print(f"  [WARN] {fpath}: {e}")

    print(f"\n  Total BLOCK generados: {total_block}")

    allow_examples = []
    for req in LEGIT_REQUESTS:
        allow_examples.append({
            "instruction": INSTRUCTION,
            "input": req,
            "output": "ALLOW | Normal HTTP request with no attack patterns detected. ###END###"
        })
    multiplier = max(1, total_block // len(LEGIT_REQUESTS))
    allow_examples = allow_examples * multiplier
    random.shuffle(allow_examples)
    allow_examples = allow_examples[:total_block]
    examples += allow_examples
    print(f"  Total ALLOW generados: {len(allow_examples)}")
    print(f"  Total ejemplos: {len(examples)}")
    return examples

def main():
    os.makedirs(os.path.dirname(OUTPUT_TRAIN), exist_ok=True)
    random.seed(RANDOM_SEED)

    print("\n[1/3] Extrayendo payloads del repositorio...")
    examples = build_dataset()

    print("\n[2/3] Shuffling y split train/eval...")
    random.shuffle(examples)
    split_idx  = int(len(examples) * (1 - EVAL_SPLIT))
    train_data = examples[:split_idx]
    eval_data  = examples[split_idx:]

    print(f"  Train: {len(train_data)} ejemplos")
    print(f"  Eval:  {len(eval_data)} ejemplos")

    print("\n[3/3] Escribiendo archivos JSONL...")
    with open(OUTPUT_TRAIN, "w", encoding="utf-8") as f:
        for ex in train_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    with open(OUTPUT_EVAL, "w", encoding="utf-8") as f:
        for ex in eval_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\n✅ Dataset generado:")
    print(f"   {OUTPUT_TRAIN}")
    print(f"   {OUTPUT_EVAL}")

    print("\n── Ejemplo BLOCK ──")
    block_ex = next((e for e in train_data if e["output"].startswith("BLOCK")), None)
    if block_ex:
        print(json.dumps(block_ex, indent=2, ensure_ascii=False))

    print("\n── Ejemplo ALLOW ──")
    allow_ex = next((e for e in train_data if e["output"].startswith("ALLOW")), None)
    if allow_ex:
        print(json.dumps(allow_ex, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
