# firewall-IA — Inline AI-Powered Application-Layer HTTP Security Gateway

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Model](https://img.shields.io/badge/Model-TinyLlama--1.1B-orange?logo=huggingface&logoColor=white)
![Fine-tuning](https://img.shields.io/badge/Fine--tuning-QLoRA%204--bit-green)
![Status](https://img.shields.io/badge/Status-no%20trained%20baseline-red)
![Dataset](https://img.shields.io/badge/Dataset%20gate-FAIL-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

An **inline AI-powered application-layer security gateway for HTTP traffic**. It classifies
individual HTTP requests in real time using a fine-tuned small language model, and is intended
to run on embedded Linux hardware via **llama.cpp**.

The device operates as an **authorized inline security gateway** — a legitimate supervisor
performing authorized inline interception, not a man-in-the-middle attack.

**Scope boundaries — please read before citing this project:**

- It inspects **HTTP at the application layer**. It does not inspect raw TCP, and it is
  **not** a replacement for a conventional stateful network firewall.
- The classifier is **stateless at the application-request level**: each request is classified
  independently, with no session or behavioural context carried across requests. Being inline
  does not make it stateful.
- It is a research prototype, not a hardened production NGFW/WAF.

---

## ⚠️ Current status (2026-08-16)

**There is no trained model in this project, and therefore no experimental baseline.**

| | |
|---|---|
| Trained adapter on disk | **none** — `model-output-v3/` does not exist |
| Dataset integrity gate (E0) | **FAIL** — see `reports/e0_dataset_integrity_current.txt` |
| Training | **blocked** — `finetune.py` is API-incompatible with the installed TRL 1.4 / transformers 5.8 |
| Historical ~91% result | **historical context only, not a baseline** — see below |

A 2026-08-16 audit established that the current dataset contains a label-determining artifact:
a classifier reading **only the `Host` header**, never the payload, scores **93.72%** on the
eval split — higher than the 91% once attributed to the model. The eval split also shares
**26.65%** of its rows verbatim with the training split.

Consequently **any accuracy number measured on the current dataset is uninterpretable as
evidence of attack detection.** Remediation is under way; see `DECISIONS.md` and `CONTEXT.md`.

**Gate rule: no training run starts while `check_dataset.py` reports FAIL.**

---

## How It Works

```
Client ──► [ firewall-IA inline gateway ] ──► Destination application / server
                        │
              Data plane: inline HTTP interception (planned: mitmproxy)
                        │
              Control plane: FastAPI classification service
                        │
                 TinyLlama 1.1B (QLoRA fine-tuned)
                        │
              ┌─────────┴─────────┐
              │                   │
       ALLOW | <reason>    BLOCK | <reason>
              │                   │
           Forward            Drop / Log
```

Each HTTP request is formatted as a prompt and fed to the fine-tuned model, which returns a
verdict in a strict format:

```
ALLOW | Normal HTTP request with no attack patterns detected.
BLOCK | SQL injection payload detected.
```

> The `###END###` suffix that appears in the current dataset is **being removed** — it is
> structurally untrainable under the current LoRA configuration. See `DECISIONS.md` D5.

**Failure behaviour is FAIL-CLOSED** (`DECISIONS.md` D4): if the classifier times out,
crashes, is unavailable, or returns an invalid decision, traffic is blocked by default.

**Design latency target** (`DECISIONS.md` D3): end-to-end added latency **P95 ≤ 200 ms**.
This is a target, not a demonstrated capability — it has not been measured, because no model
exists to measure.

---

## Attack Categories in the Dataset

19 attack categories are represented. **Representation is severely uneven** — the table below
gives measured volumes from the current dataset, not a claim of detection capability.

| Category | Example Payload | Examples | % of dataset |
|---|---|---:|---:|
| Path Traversal | `../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd` | 24,176 | 24.39% |
| File Inclusion | `../../../../etc/passwd`, `php://filter/` | 8,447 | 8.52% |
| SQL Injection | `' OR '1'='1`, `UNION SELECT`, `DROP TABLE` | 7,040 | 7.10% |
| XSS Injection | `<script>alert('xss')</script>` | 4,124 | 4.16% |
| Command Injection | `; cat /etc/passwd`, `\| whoami` | 1,469 | 1.48% |
| CRLF Injection | `%0d%0aSet-Cookie: session=hijacked` | 744 | 0.75% |
| Server-Side Template Injection | `{{7*7}}`, `{{config.__class__...}}` | 697 | 0.70% |
| Insecure Deserialization | Java serialized objects, PHP object injection | 414 | 0.42% |
| HTTP Parameter Pollution | `?id=1&id=2&id=admin` | 400 | 0.40% |
| Open Redirect | `?redirect=https://evil.com` | 391 | 0.39% |
| XXE Injection | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | 381 | 0.38% |
| SSRF | `url=http://169.254.169.254/latest/meta-data/` | 312 | 0.31% |
| XPath Injection | `' or '1'='1`, `'] \| //* \| //*['` | 301 | 0.30% |
| JWT Attacks | `alg:none` bypass, forged signatures | 196 | 0.20% |
| NoSQL Injection | `{"$gt":""}`, `{"$where":"this.role=='admin'"}` | 135 | 0.14% |
| LDAP Injection | `*)(uid=*))(\|(uid=*` | 123 | 0.12% |
| GraphQL Injection | `__schema` introspection, nested queries | 118 | 0.12% |
| HTTP Request Smuggling | CL.TE and TE.CL desync attacks | 52 | 0.05% |
| CSRF | Forged cross-origin POST, null-origin bypass | 46 | 0.05% |

**Path Traversal to CSRF is a 525:1 ratio.** Six categories sit below 0.25% of the dataset.
Re-measure with `check_dataset.py` after any regeneration rather than quoting this table.

---

## Known Limitations

### Blocking — dataset validity

- **Envelope shortcuts.** `Host` alone predicts the label at 93.72% on eval; `Content-Type`
  (82.62%), header-name set (76.84%), header count (75.88%), body presence (74.12%) and HTTP
  method (74.06%) are independent shortcuts of the same kind. Attack examples all carry
  `Host: target.internal.com`; synthetic benign examples never do.
- **Train/eval leakage of 26.65%**, concentrated in 253 replicated template strings. Each
  split is also ~26% internally duplicated.
- **Benign traffic diversity is 240 unique synthetic strings** (replicated ~110×) plus CSIC
  2010 normals from a single 2010 Spanish e-commerce app with one host, one User-Agent and
  one cookie pattern.
- **Label noise.** The markdown scraper accepts prose lines, not only fenced code blocks; some
  path-traversal examples are raw fuzzing-wordlist entries containing unresolved `{FILE}`
  placeholders.
- **Dataset generation is not reproducible** despite `random.seed(42)` — consumption order
  depends on `PYTHONHASHSEED` and on unsorted `os.listdir()`/`os.walk()`.

### Blocking — tooling

- **`finetune.py` will not run** on the installed stack: TRL 1.4's `SFTTrainer` rejects
  `dataset_text_field`, `max_seq_length` and `tokenizer`.
- **`###END###` is structurally untrainable**: the resized embedding rows are neither in
  `target_modules` nor `modules_to_save`, so they receive no gradient, are never saved, and
  are re-randomised on every load.

### Evaluation

- **The 135-case test suite is 109 BLOCK / 26 ALLOW.** An always-BLOCK classifier scores
  80.7% on it. The 26 ALLOW cases cannot support a false-positive-rate claim — 0/26 has a 95%
  upper bound of roughly 11% FPR.
- **5 cases per category** gives 20 pp resolution; a "40%" per-category score is 2 of 5.
- **The adversarial suite is in-distribution** — it reuses the same transform families present
  in training, so it measures learned transforms rather than evasion resistance.
- **Metric set is incomplete**: accuracy / FP count / FN count only. No precision, recall, F1,
  FPR, FNR or confusion matrix; latency has no P95/P99.

### Scope

- **No TLS termination**: encrypted traffic cannot be inspected without a separate TLS
  termination layer.
- **Not tested on physical embedded hardware.** llama.cpp deployment is pending, and the
  target platform (Raspberry Pi vs NVIDIA Jetson) is deliberately **not yet chosen** — it must
  be selected from measured requirements (`DECISIONS.md` D10).
- **Stateless only.** Session-aware / behavioural detection is explicitly out of current scope.

---

## Tech Stack

| Component | Technology |
|---|---|
| Base model | TinyLlama/TinyLlama-1.1B-Chat-v1.0 |
| Fine-tuning method | QLoRA (4-bit NF4 quantization) |
| Training framework | HuggingFace PEFT + TRL (`SFTTrainer`) |
| Training data sources | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + CSIC 2010 + synthetic templates |
| Control plane | FastAPI (`classifier_api.py`) |
| Data plane | inline HTTP interception — **planned**, not implemented |
| Inference (current) | HuggingFace Transformers + PEFT adapter |
| Target deployment | llama.cpp (GGUF Q4_K_M) on embedded Linux |
| Development hardware | NVIDIA RTX 4090 Laptop (Lenovo Legion Pro 7) |
| OS / Python | Ubuntu · **Python 3.12 explicitly** (`python3` resolves to 3.14, which lacks the ML stack) |

Installed and verified 2026-08-16: torch 2.6.0+cu124, transformers 5.8.0, trl 1.4.0,
peft 0.19.1, bitsandbytes 0.49.2, accelerate 1.13.0, datasets 4.8.5. There is no
`requirements.txt`; pinning one is outstanding work.

---

## Historical Training Results — SUPERSEDED

> **These results are preserved as historical evidence. They are NOT the current baseline and
> must not be used as a comparison point for future versions.**
>
> The v1/v2/v3 adapters and the exact v3 dataset were lost in an OS reinstall (all were
> gitignored). The original v3 is not reproducible bit-for-bit. Its numbers were also measured
> on a dataset now known to contain the envelope shortcut described above, and on a test suite
> whose composition (109 BLOCK / 26 ALLOW) places a trivial always-BLOCK classifier at 80.7%.

| Metric | v2 | v3 (lost) |
|---|---|---|
| Dataset size | 33,648 (16,828 BLOCK / 16,820 ALLOW) | 52,670 (26,335 BLOCK / 26,335 ALLOW) |
| Data sources | PayloadsAllTheThings only | PayloadsAllTheThings + CSIC 2010 + synthetic |
| Attack categories | 14 | 19 (Path Traversal + CSRF were silently **absent**) |
| Epochs | 4 | 4 |
| Final train loss | 0.2837 | 0.2036 |
| Best eval loss | 0.3289 | 0.5344 |
| Test suite accuracy | 26/26 — 26 cases | 124/135 (91%) — 135 cases |
| False positives | 0 | 0 (of only 26 ALLOW cases) |
| Inference latency (avg) | not measured | ~799.7 ms avg — **confounded**, inflated by forced 40-token generation |
| Training time | ~78 min | ~8 hours |

The current dataset (99,132 examples) is larger than v3's because two PayloadsAllTheThings
directories had been renamed upstream and were silently skipped. Fixing the folder names added
~46,000 examples — **predominantly Directory Traversal and related file-path data. CSRF gained
only 46 examples and remains effectively untrained.**

---

## Project Structure

```
firewall-IA/
├── CONTEXT.md            # Project memory / source of truth. Read this first.
├── DECISIONS.md          # Decision log D1–D10. Read before proposing changes.
│
├── parse_dataset.py      # Dataset generator: PayloadsAllTheThings .md/.txt + hardcoded
│                         # categories + synthetic ALLOW + CSIC 2010 integration +
│                         # 8 obfuscation transforms. Outputs train.jsonl / eval.jsonl.
│
├── check_dataset.py      # E0 DATASET INTEGRITY GATE (analysis-only, never mutates).
│                         # Duplication, train→eval leakage, envelope confounds,
│                         # trivial baselines, SHA-256 manifest. PASS/WARNING/FAIL.
│
├── finetune.py           # QLoRA fine-tune via PEFT + SFTTrainer. Requires CUDA.
│                         # ⚠️ Currently incompatible with installed TRL/transformers.
│
├── test_model.py         # 135-case test harness (95 systematic + 20 adversarial +
│                         # 20 false-positive) + latency benchmark.
│
├── classifier_api.py     # FastAPI control plane wrapping the classifier.
│                         # Built but never executed — no adapter exists.
│
├── csic_database.csv     # CSIC 2010 HTTP dataset (61,065 requests).
├── train.jsonl           # Generated dataset — currently TRACKED (see note below).
├── eval.jsonl            # Generated dataset — currently TRACKED (see note below).
└── reports/              # Experiment and audit outputs. Never overwrite; add new files.
```

> **Note on dataset tracking.** `.gitignore` lists `train.jsonl` and `eval.jsonl`, but both
> files are in fact **tracked** — `.gitignore` has no effect on already-tracked files. This is
> currently the only reason the dataset survives, since the v3 dataset was lost precisely
> because it was gitignored. Per `DECISIONS.md` D6 they are **not** to be untracked until a
> manifest-based reproducibility scheme is documented and in place.

---

## Quickstart

> **Use `python3.12` explicitly.** `python3` resolves to Python 3.14 on this machine, which
> does not have the ML stack. No virtual environments are used (project preference).

### 1. Install dependencies

```bash
python3.12 -m pip install torch transformers peft trl bitsandbytes datasets accelerate pandas fastapi uvicorn --break-system-packages
```

### 2. Clone the payload repository

```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/PayloadsAllTheThings
```

The current dataset was generated at PayloadsAllTheThings commit
`e961fef231d8327bae83b563fab50aec2e6b77c0`. Check that commit out to reproduce it.

### 3. Check dataset integrity — run this first

```bash
python3.12 check_dataset.py --out reports/e0_dataset_integrity_$(date +%Y%m%d).txt
```

Exit codes: `0` PASS · `1` WARNING · `2` FAIL. **Against the current dataset this reports
FAIL, which is the expected and correct outcome.**

### 4. Generate the dataset

```bash
python3.12 parse_dataset.py
```

Outputs `train.jsonl` and `eval.jsonl` in the project directory. Treat any `[SKIP] Carpeta no
encontrada` line as an **error**, not a warning — that failure mode silently removed two
attack categories from v3.

### 5. Fine-tune the model

```bash
python3.12 finetune.py
```

⚠️ **Currently fails on the installed stack.** Porting to `SFTConfig` / `processing_class` is
outstanding work.

### 6. Run the test suite

```bash
python3.12 test_model.py
```

Requires a trained adapter at `model-output-v3/`, which does not currently exist.

---

## Roadmap

Ordered experiment sequence. Scope decisions are recorded in `DECISIONS.md`.

- [x] **E0 — Dataset integrity gate** — `check_dataset.py`; current dataset reports **FAIL**
- [ ] **E1 — Port `finetune.py`** to TRL 1.4 / transformers 5.8 — *hard blocker for all training*
- [ ] **E2 — Envelope ablation** — regenerate with shared envelope distributions across both
      classes (D1), retrain, compare. *The decisive experiment.*
- [ ] **E3 — Leakage-free split** — deduplicate and split on a payload-identity key so
      obfuscated/wrapped variants of one payload cannot straddle the split
- [ ] **E4 — Remove `###END###`** (D5) and use native termination
- [ ] **E5 — Per-category rebalancing** — address the 525:1 spread, including CSRF, request
      smuggling, GraphQL, LDAP, NoSQL and JWT
- [ ] **E6 — Held-out evasion evaluation** — transforms and base payloads not seen in training
- [ ] **E8 — Quantization tradeoff** — FP16 baseline vs GGUF Q4_K_M
- [ ] **E9 — Inline pipeline + overhead decomposition** — model-only / model+API / proxy /
      end-to-end, each with P50, P95, P99 and throughput (D3)
- [ ] **Physical embedded deployment** — platform selected from measured requirements (D10)
- [ ] **Expanded evaluation harness** — precision, recall, F1, FPR, FNR, confusion matrix;
      more ALLOW cases; ≥20 cases per category
- [ ] *(Future / optional, D9)* Conventional rule-based comparison
- [ ] *(Future, D2)* Experiment on the 18,478 CSIC anomalies the keyword categorizer could not
      classify
- [ ] *(Future)* Structured security telemetry / SIEM integration
- [ ] *(Future)* Stateful, session-aware classification

---

## Research Framing

The question this project aims to answer is measurable:

> Can a lightweight AI-based application-layer security gateway detect malicious HTTP traffic
> with competitive security effectiveness while maintaining acceptable latency, throughput and
> resource consumption in an inline deployment?

This is a **hypothesis, not a conclusion**. No claim that this system is more secure or faster
than a conventional mechanism should be made unless an experiment in `reports/` demonstrates
it, under stated conditions.

Per `DECISIONS.md` D7, removing dataset artifacts is expected to reduce measured accuracy, and
that is an accepted outcome: a valid lower number is worth more than an invalid higher one.

---

## Credits

- Training data: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo)
- CSIC 2010 HTTP dataset (Spanish Research National Council)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl)
