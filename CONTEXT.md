# firewall-IA — Session Context for Claude Code

## 1. Project Overview

firewall-IA is a fine-tuned TinyLlama-1.1B-Chat classifier trained to act as an HTTP request firewall. Given a raw HTTP request string, it outputs `ALLOW | <reason> ###END###` or `BLOCK | <reason> ###END###`. The model is trained via LoRA (4-bit quantized) using supervised fine-tuning on a labeled dataset of real and synthetic HTTP traffic. The end goal is a GGUF-exported model that can be embedded in an HTTP proxy layer for real-time traffic classification.

---

## 2. Current State (as of 2026-04-29)

### Model Versions

| Version | Location | Status |
|---------|----------|--------|
| v1 | `~/Desktop/firewall-IA/model-output/` | Trained, superseded |
| v2 | `~/Desktop/firewall-IA/model-output-v2/` | **Last trained model** — adapter + 10 checkpoints (200–2000 steps) |
| v3 | does not exist yet | **Pending** — dataset is ready, training not started |

`test_model.py` currently loads `model-output-v2`. Update `ADAPTER_DIR` before testing v3.

### Dataset — Current (v3-ready)

| Split | Path | Lines |
|-------|------|------:|
| Train | `~/ai-firewall/train.jsonl` | 42,136 |
| Eval  | `~/ai-firewall/eval.jsonl`  | 10,534 |
| **Total** | | **52,670** |

BLOCK: 26,335 | ALLOW: 26,335 | exact 1:1 balance.

**WARNING:** `~/Desktop/firewall-IA/train.jsonl` and `eval.jsonl` are **stale copies** from a previous run (10,953 lines, dated 2026-04-12). Do not use them. `finetune.py` and `parse_dataset.py` both point to `~/ai-firewall/` which is correct.

### Data Sources

1. **PayloadsAllTheThings** (`~/PayloadsAllTheThings/`) — `.md` code blocks + heuristic lines + `.txt` payload files across 14 active category directories
2. **Hardcoded payloads** (in `parse_dataset.py`) — CRLF (30), HPP (20 param sets × 10 paths), XPath (35)
3. **241 synthetic LEGIT_REQUESTS templates** (in `parse_dataset.py`) — hand-written REST API, auth, mobile, GraphQL, webhook, false-positive mitigations; multiplied 73× then trimmed
4. **CSIC 2010 HTTP dataset** (`csic_database.csv`) — 61,065 real HTTP requests from a Spanish e-commerce web app; 36,000 Normal (ALLOW) + 25,065 Anomalous (BLOCK, filtered)

### Attack Categories Covered — 17 total

From PayloadsAllTheThings (14):
- SQL Injection, XSS Injection, Command Injection, LDAP Injection, XXE Injection, Open Redirect, Server Side Request Forgery, JSON Web Token, GraphQL Injection, NoSQL Injection, Server Side Template Injection, File Inclusion, Insecure Deserialization, Request Smuggling

Hardcoded (3):
- CRLF Injection, HTTP Parameter Pollution, XPath Injection

**MISSING (zero examples):**
- `Path Traversal` — PayloadsAllTheThings directory not found at runtime
- `CSRF Injection` — PayloadsAllTheThings directory not found at runtime; not in CSIC either

---

## 3. Files and What They Do

### `parse_dataset.py`
Generates `~/ai-firewall/train.jsonl` and `~/ai-firewall/eval.jsonl`. Run with `python3 parse_dataset.py`.

Key functions:
- `build_dataset()` — extracts payloads from PayloadsAllTheThings + hardcoded categories; generates synthetic ALLOW pool
- `build_obfuscated_examples(raw_block_payloads, 2000)` — applies 8 obfuscation transforms (URL encode, double-encode, unicode, case variation, SQL comment inject, whitespace tab, bash IFS, HTML entity) to produce 2,000 obfuscated BLOCK variants
- `categorize_csic_anomalous(request_str)` — 11-rule heuristic classifier; checks raw and `unquote_plus()`-decoded request string; returns specific BLOCK label or generic fallback
- `integrate_csic2010(filepath)` — reads CSV, reconstructs HTTP request strings (normalizes host → `target.com`, strips `/tienda1` path prefix), routes Normal→ALLOW and Anomalous→BLOCK (filtered); prints breakdown and samples
- `main()` — orchestrates pipeline: build → obfuscate → integrate CSIC → merge pools → rebalance to 1:1 min-trim → shuffle → split 80/20 → write JSONL

### `finetune.py`
Fine-tunes TinyLlama-1.1B-Chat with LoRA (4-bit NF4, rank=16, alpha=32). Run with `python3 finetune.py`. ~91 minutes on current hardware.

Key config (lines 14–17):
```
TRAIN_FILE = ~/ai-firewall/train.jsonl
EVAL_FILE  = ~/ai-firewall/eval.jsonl
OUTPUT_DIR = ~/Desktop/firewall-IA/model-output-v2   ← MUST UPDATE TO v3 BEFORE TRAINING
```

Training: 4 epochs, batch 8, grad accum 4, lr 2e-4 cosine, FP16, paged_adamw_8bit. Adds `###END###` as special token. Evaluates every 200 steps. Uses SFTTrainer.

### `test_model.py`
Loads `model-output-v2` (base TinyLlama + merged LoRA adapter), runs 26-case test suite (22 BLOCK, 4 ALLOW) plus 12 adversarial cases (4 obfuscated, 4 unseen categories, 4 false-positive mitigations). Reports accuracy.

Key config (lines 8–9):
```
BASE_MODEL  = TinyLlama/TinyLlama-1.1B-Chat-v1.0
ADAPTER_DIR = ~/Desktop/firewall-IA/model-output-v2   ← UPDATE TO v3 AFTER TRAINING
```

Inference: greedy decode, max 40 new tokens, stops at `###END###` token. Extracts decision via regex `(ALLOW|BLOCK)\s*\|\s*(.+?)(?:\s*###END###|\.|$)`.

### `csic_database.csv`
CSIC 2010 HTTP Intrusion Detection Dataset. 61,065 rows × 17 columns. Label column is `Unnamed: 0` (string: `"Normal"` / `"Anomalous"`). Key columns used: `Method`, `URL`, `User-Agent`, `cookie`, `content-type`, `content`. `URL` field format: `http://localhost:8080/tienda1/path?query HTTP/1.1` (full URL + HTTP version in one cell). Column `lenght` is a typo in the original data.

### `model-output-v2/`
Last trained LoRA adapter. Contains `adapter_config.json`, `adapter_model.safetensors`, `added_tokens.json` (includes `###END###`), `tokenizer_config.json`, and checkpoints at steps 200, 400, ..., 2000. This was trained on the pre-CSIC dataset (synthetic only, ~39,341 examples).

### `~/ai-firewall/train.jsonl` / `eval.jsonl`
Current dataset, generated by the most recent `parse_dataset.py` run. Each line is a JSON object: `{"instruction": "...", "input": "<HTTP request string>", "output": "ALLOW|BLOCK | <reason> ###END###"}`. Ready for v3 training. Do not confuse with the stale copies at `~/Desktop/firewall-IA/train.jsonl`.

---

## 4. Changes Made in This Session (applied to `parse_dataset.py`)

1. **Added `CSIC_PATH` constant** (line 10) — `os.path.join(os.path.dirname(os.path.abspath(__file__)), "csic_database.csv")`. Makes the CSV path relative to the script, not the working directory.

2. **Added `integrate_csic2010(filepath)`** — full HTTP request reconstruction from CSV rows, host normalization, path prefix stripping, optional header appending, NaN-safe column access. Routes to ALLOW or BLOCK pool. Prints category breakdown and samples.

3. **Added `categorize_csic_anomalous(request_str)`** — 11-rule heuristic (SQL→XSS→Command→PathTraversal→LDAP→XXE→SSRF→NoSQL→CRLF→HPP→fallback). Checks both raw lowercase string and `unquote_plus()`-decoded string in one `has()` call. HPP rule uses structural check (`len(params) != len(set(params))`), not keywords.

4. **Rewrote `main()` balancing logic** — replaced old per-step approach (ALLOW multiplied inside `build_dataset()`, extra_allow added for obfuscated BLOCK) with end-of-pipeline single `min(len(block_pool), len(allow_pool))` trim applied after all sources are merged. Corrects the previous 155-example BLOCK surplus.

5. **Filtered generic-fallback CSIC Anomalous rows** — in `integrate_csic2010()`, rows where `categorize_csic_anomalous()` returns `"BLOCK | Anomalous HTTP request detected. ###END###"` are counted but `continue`d — not added to `block_examples`. Reduces CSIC BLOCK contribution from 25,065 → 6,587.

---

## 5. Next Steps in Order

1. **Update `finetune.py` OUTPUT_DIR** — change line 17 from `model-output-v2` to `model-output-v3` before training. Also update `test_model.py` ADAPTER_DIR after training completes.

2. **Train v3** — `python3 finetune.py` — ~91 minutes. Reads from `~/ai-firewall/train.jsonl` (42,136 examples). Saves to `model-output-v3/`.

3. **Run test suite** — `python3 test_model.py` — 26 standard + 12 adversarial cases. Compare accuracy to v2 baseline.

4. **Build larger adversarial suite** — expand `test_model.py` to 100+ cases covering: obfuscated variants of all 17 attack categories, path traversal (currently untrained), CSRF, false-positive mitigations for CSIC-style clean traffic, polyglot payloads.

5. **GGUF export** — convert `model-output-v3/` to GGUF format for embedded inference use.

6. **Build HTTP proxy layer** — intercept real HTTP traffic, call model, apply ALLOW/BLOCK decision.

---

## 6. Known Limitations and Intentional Decisions

**CSIC User-Agent bias (intentional for v3):** All 36,000 CSIC Normal examples and all 6,587 CSIC Anomalous examples use the same User-Agent: `Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)`. This was left in deliberately for v3 to establish a baseline. Plan: measure whether v3 learns to associate this UA with ALLOW patterns, then strip/randomize UAs in v4 dataset and measure delta.

**18,478 CSIC Anomalous excluded:** These are buffer overflow (long field values), integer tampering (negative/fractional quantities), and cookie poisoning attacks where the anomaly is purely structural — no keyword-detectable payload. The generic label "Anomalous HTTP request detected" cannot be validated from the request content, so these rows were excluded. They represent 73.7% of CSIC Anomalous rows.

**~27,258 ALLOW examples trimmed for balance:** After merging 17,593 synthetic + 36,000 CSIC Normal = 53,593 ALLOW, the pool was trimmed to 26,335 to match the BLOCK count. The trim is random (seed=42, deterministic). Approximately 8,742 CSIC Normal and 17,593 synthetic survive — but exact split is non-deterministic from the user's perspective. Trimmed examples are simply discarded, not archived.

**BLOCK pool is the size-limiting factor:** BLOCK = 26,335. ALLOW was 53,593 before trim. Increasing dataset size requires more BLOCK sources, not more ALLOW. Adding Path Traversal, CSRF, and remaining CSIC structural attacks would increase BLOCK and unlock more ALLOW examples.

**CSIC attack diversity is narrow:** 4,627 SQL injection CSIC examples are predominantly the same payload (`DROP TABLE usuarios / SELECT * FROM datos`) inserted into the `cantidad` parameter of the same JSP endpoint. Adds volume but limited variety.

**`--` SQL keyword is broad:** The SQL injection rule in `categorize_csic_anomalous()` triggers on `--`. This is a SQL comment marker but also appears in HTML comments and some legitimate URLs. Acceptable for CSIC's e-commerce context; revisit if extended to other datasets.

**Path Traversal and CSRF are completely uncovered:** `~/PayloadsAllTheThings/Path Traversal/` and `~/PayloadsAllTheThings/CSRF Injection/` directories do not exist. Zero training examples for either category. The model will not have learned to block these. Check directory names in the repo — may be named differently (e.g., `Directory Traversal`, `Cross-Site Request Forgery`).

---

## 7. How to Re-Orient at the Start of a New Session

1. Read this file first.
2. Read `parse_dataset.py` (current dataset logic) and `finetune.py` (training config).
3. Run `ls ~/Desktop/firewall-IA/model-output-v3/ 2>/dev/null || echo "v3 not trained yet"` to check training status.
4. Run `wc -l ~/ai-firewall/train.jsonl` to confirm current dataset size (expect 42,136 for v3-ready state).
5. Check `~/PayloadsAllTheThings/` directory names with `ls ~/PayloadsAllTheThings/` to find the correct folder names for Path Traversal and CSRF before assuming they are missing.
6. Do not assume `model-output-v2/` is the latest — check for `model-output-v3/` or later.
