# firewall-IA — AI-Powered Network Firewall

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Model](https://img.shields.io/badge/Model-TinyLlama--1.1B-orange?logo=huggingface&logoColor=white)
![Fine-tuning](https://img.shields.io/badge/Fine--tuning-QLoRA%204--bit-green)
![CUDA](https://img.shields.io/badge/CUDA-12.2-76b900?logo=nvidia&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

An inline AI supervisor that classifies HTTP/HTTPS and TCP traffic in real time using a fine-tuned large language model. Designed to run on embedded systems with low resources via **llama.cpp**, it acts as an authorized gateway between the internet and an internal network — not a man-in-the-middle attack, but a legitimate inline traffic supervisor.

---

## How It Works

```
Internet ──► [ firewall-IA ] ──► Internal Network
                   │
         HTTP request arrives
                   │
         Fed to TinyLlama 1.1B
         (fine-tuned on 52k attacks)
                   │
          ┌────────┴────────┐
          │                 │
   ALLOW | <reason>   BLOCK | <reason>
          │                 │
       Forward           Drop / Log
```

Every HTTP request that passes through the firewall is formatted as a prompt and fed to the fine-tuned model. The model outputs a verdict in a strict format:

```
ALLOW | Normal HTTP request with no attack patterns detected. ###END###
BLOCK | SQL injection payload detected. ###END###
```

The firewall parses the verdict and acts on it immediately — forwarding legitimate traffic and dropping or logging malicious requests.

---

## Detected Attack Categories (v3 Model)

| Category | Example Payload |
|---|---|
| SQL Injection | `' OR '1'='1`, `UNION SELECT`, `DROP TABLE` |
| XSS Injection | `<script>alert('xss')</script>` |
| Command Injection | `; cat /etc/passwd`, `\| whoami` |
| LDAP Injection | `*)(uid=*))(|(uid=*` |
| XXE Injection | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| Open Redirect | `?redirect=https://evil.com` |
| SSRF | `url=http://169.254.169.254/latest/meta-data/` |
| JWT Attacks | `alg:none` bypass, forged signatures |
| GraphQL Injection | `__schema` introspection, nested queries |
| NoSQL Injection | `{"$gt":""}`, `{"$where":"this.role=='admin'"}` |
| Server-Side Template Injection | `{{7*7}}`, `{{config.__class__...}}` |
| File Inclusion | `../../../../etc/passwd`, `php://filter/` |
| Insecure Deserialization | Java serialized objects, PHP object injection |
| HTTP Request Smuggling | CL.TE and TE.CL desync attacks |
| CRLF Injection | `%0d%0aSet-Cookie: session=hijacked` |
| HTTP Parameter Pollution | `?id=1&id=2&id=admin` |
| XPath Injection | `' or '1'='1`, `'] \| //* \| //*['` |
| Path Traversal | `../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd` |
| CSRF | Forged cross-origin POST, null-origin bypass |

---

## Known Limitations

- **No SSL termination**: Encrypted traffic cannot be inspected without a separate TLS termination layer.
- **Not a production NGFW/WAF replacement**: This is a research and embedded-systems project, not a hardened enterprise solution.
- **No obfuscated/encoded variants yet**: The model has not been trained on URL-encoded, base64-encoded, or otherwise obfuscated attack payloads.
- **Request Smuggling reason string**: The model correctly BLOCKs HTTP Request Smuggling attempts but may output a different attack category label in the reason string (e.g., "SQL injection" instead of "HTTP request smuggling"). The blocking verdict is always correct.
- **Not yet tested on physical embedded hardware**: All testing has been done on desktop GPU hardware. llama.cpp deployment on embedded Linux targets is pending.
- **JWT detection is blind to base64-encoded token content**: The model cannot detect `alg:none`, `kid` path traversal, or forged signature attacks — the malicious signal is inside the encoded token payload. v3 scores 0% on JWT attack cases. Dedicated training examples are needed for v4.
- **CSRF detection is unreliable**: Zero training examples exist for this category. The model has no signal from Origin/Referer headers. v3 scores 40% on CSRF cases by chance pattern matching only.
- **GraphQL introspection not reliably distinguished from benign GraphQL queries**: The model allows `__schema` introspection in some cases. v3 scores 60% on GraphQL attack cases.

---

## Tech Stack

| Component | Technology |
|---|---|
| Base model | TinyLlama/TinyLlama-1.1B-Chat-v1.0 |
| Fine-tuning method | QLoRA (4-bit NF4 quantization) |
| Training framework | HuggingFace PEFT + TRL (`SFTTrainer`) |
| Training data source | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| Inference | HuggingFace Transformers + PEFT adapter |
| Target deployment | llama.cpp on embedded Linux |
| Training hardware | NVIDIA RTX 4090 Laptop (16 GB VRAM) |
| CUDA version | 12.2 |
| OS | Ubuntu 24 |

---

## Training Results

| Metric | v2 | v3 |
|---|---|---|
| Dataset size | 33,648 (16,828 BLOCK / 16,820 ALLOW) | 52,670 (26,335 BLOCK / 26,335 ALLOW) |
| Data sources | PayloadsAllTheThings only | PayloadsAllTheThings + CSIC 2010 + synthetic templates |
| Attack categories | 14 | 19 |
| Epochs | 4 | 4 |
| Final train loss | 0.2837 | 0.2036 |
| Best eval loss | 0.3289 | 0.5344 |
| Test suite accuracy | 26/26 (100%) — 26 cases | 124/135 (91%) — 135 cases |
| False positives | 0 | 0 |
| Inference latency (avg) | not measured | avg 799.7ms \| min 787.2ms \| max 825.6ms \| std 7.5ms (HuggingFace Transformers, RTX 4090 Laptop) |
| Training time | ~78 min | ~8 hours (5:30 PM – 1:30 AM) |

> **Note on eval loss:** v3's eval loss (0.5344) is higher than v2's (0.3289). This is because the v3 eval set is significantly larger and more diverse (10,534 vs ~2,700 examples), making direct comparison of raw loss values misleading. Accuracy on the expanded test suite is the more reliable indicator.

---

## Project Structure

```
firewall-IA/
├── parse_dataset.py    # Dataset generator: parses PayloadsAllTheThings .md/.txt files,
│                       # wraps payloads in simulated HTTP requests, labels them BLOCK.
│                       # Generates balanced ALLOW examples from synthetic legitimate traffic.
│                       # Outputs train.jsonl and eval.jsonl.
│
├── finetune.py         # Fine-tuning script: loads TinyLlama-1.1B-Chat, applies 4-bit QLoRA
│                       # via PEFT, and trains with SFTTrainer. Saves the LoRA adapter to
│                       # model-output-v2/. Requires CUDA GPU.
│
├── test_model.py       # Inference test harness: loads the fine-tuned adapter, runs 135-case
│                       # comprehensive test suite (95 systematic BLOCK cases across 19
│                       # categories, 20 adversarial cases, 20 false-positive stress tests).
│                       # Reports per-case verdict, per-category accuracy, and inference benchmark.
│
├── .gitignore          # Excludes model weights, generated datasets, Python cache, and venvs.
│
└── README.md           # This file.
```

> **Not tracked by git** (see `.gitignore`): `train.jsonl`, `eval.jsonl`, `model-output*/`

---

## Quickstart

### 1. Install dependencies

```bash
pip install torch transformers peft trl bitsandbytes datasets accelerate
```

### 2. Clone the payload repository

```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/PayloadsAllTheThings
```

### 3. Generate the dataset

```bash
python parse_dataset.py
# Outputs: ~/ai-firewall/train.jsonl and eval.jsonl
```

### 4. Fine-tune the model

```bash
python finetune.py
# Requires a CUDA GPU. Adapter saved to: ~/Desktop/firewall-IA/model-output-v2/
```

### 5. Run the test suite

```bash
python test_model.py
# Expected: 26/26 (100%) accuracy
```

---

## Roadmap

- [ ] **GGUF export** — Convert the fine-tuned adapter to GGUF format for llama.cpp inference on CPU/embedded targets
- [ ] **Inline proxy interceptor** — Build the actual HTTP proxy layer that feeds live traffic into the model and enforces verdicts in real time
- [ ] **Obfuscated attack variants** — Expand the dataset with URL-encoded, Unicode-escaped, base64, and double-encoded payloads to improve evasion resistance
- [ ] **Physical embedded hardware testing** — Deploy on an ARM-based embedded Linux board and measure latency and throughput under real network conditions
- [x] **Per-category accuracy benchmarking** — done — see v3 results (91% overall, 0 false positives, failures concentrated in JWT/CSRF/GraphQL)
- [ ] **Fix JWT dataset** — add `alg:none`, `kid` injection, and forged signature training examples
- [ ] **Fix CSRF dataset** — add Origin/Referer-based examples to `parse_dataset.py`
- [ ] **Fix GraphQL dataset** — add examples distinguishing `__schema` introspection from benign queries
- [ ] **Retrain as v4** with expanded dataset targeting the four weak categories
- [ ] **Logging and alerting** — Add structured logging (JSON) and optional webhook/syslog alerts on BLOCK verdicts

---

## Credits

- Training data: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl)
