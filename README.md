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
         (fine-tuned on 33k attacks)
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

## Detected Attack Categories (v2 Model)

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

---

## Known Limitations

- **No SSL termination**: Encrypted traffic cannot be inspected without a separate TLS termination layer.
- **Not a production NGFW/WAF replacement**: This is a research and embedded-systems project, not a hardened enterprise solution.
- **No obfuscated/encoded variants yet**: The model has not been trained on URL-encoded, base64-encoded, or otherwise obfuscated attack payloads.
- **Request Smuggling reason string**: The model correctly BLOCKs HTTP Request Smuggling attempts but may output a different attack category label in the reason string (e.g., "SQL injection" instead of "HTTP request smuggling"). The blocking verdict is always correct.
- **Not yet tested on physical embedded hardware**: All testing has been done on desktop GPU hardware. llama.cpp deployment on embedded Linux targets is pending.

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

## Training Results (v2)

| Metric | Value |
|---|---|
| Dataset size | 33,648 examples (16,828 BLOCK / 16,820 ALLOW) |
| Attack categories | 14 |
| Epochs | 4 |
| Batch size | 8 (effective 32 with gradient accumulation) |
| LoRA rank | 16 |
| Final train loss | 0.2837 |
| Best eval loss | 0.3289 (at epoch 2.85) |
| Test accuracy | **26/26 (100%)** across all 14 categories |
| Training time | ~78 minutes |

Loss curve: started at 0.52 (epoch 0.12) and converged smoothly to 0.28 by epoch 4. Eval loss plateaued around epoch 2.6–2.9 with no signs of overfitting.

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
├── test_model.py       # Inference test harness: loads the fine-tuned adapter, runs 26
│                       # hand-crafted test cases (22 BLOCK, 4 ALLOW), and reports per-case
│                       # verdict + accuracy. Use this to validate any new checkpoint.
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
- [ ] **Per-category accuracy benchmarking** — Build a structured evaluation suite with pass/fail counts broken down by attack category
- [ ] **Logging and alerting** — Add structured logging (JSON) and optional webhook/syslog alerts on BLOCK verdicts

---

## Credits

- Training data: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl)
