# firewall-IA — Session Context for Claude Code

## 1. Project Overview

**Project identity: an inline AI-powered application-layer security gateway for HTTP traffic.**

The system is conceptually comparable to an application firewall / WAF-like security mechanism. It is **NOT** a replacement for a conventional stateful network firewall, and must not be described as one. The classifier is **stateless at the application-request level** — each HTTP request is classified independently, with no session context carried across requests. Being inline does not make it stateful.

firewall-IA is a fine-tuned TinyLlama-1.1B-Chat classifier. Given a raw HTTP request string, it outputs `ALLOW | <reason>` or `BLOCK | <reason>`, terminating on the model's native EOS (the `###END###` suffix was removed in E4 — see D5 in `DECISIONS.md`). The model is trained via LoRA (4-bit quantized) using supervised fine-tuning on a labeled dataset of real and synthetic HTTP traffic. The end goal is a GGUF-exported model embedded behind an inline HTTP proxy for real-time application-layer classification.

The device is an **authorized inline supervisor (a legitimate security gateway), NOT a man-in-the-middle.** Maintain this distinction in all design discussion. Distinguish between: MITM attack / authorized inline interception / reverse proxy / security gateway / application-layer inspection. This project uses **authorized inline interception**.

> **Companion documents:**
> - `DECISIONS.md` — the project decision log (D1–D18). Read it before proposing architectural changes.
> - `reports/` — experiment and audit outputs. Never overwrite a report; add a new one.

---

## 2. ENVIRONMENT — CRITICAL (post-Ubuntu-reinstall, 2026-05-24)

**The machine was reinstalled. The Python environment changed and this WILL bite you if ignored.**

- `python3` resolves to **Python 3.14** (`/usr/bin/python3`) — the ML stack is NOT installed here.
- The ML stack lives in **Python 3.12** (`/usr/bin/python3.12`, packages in `~/.local/lib/python3.12/site-packages`).
- **ALWAYS invoke `python3.12` explicitly** to run scripts: `python3.12 finetune.py`. Never `python3`.
- **ALWAYS install with `python3.12 -m pip install <pkg> --break-system-packages`.** Plain `pip` currently maps to 3.12 but `python3.12 -m pip` is unambiguous.
- Verify pip target anytime with `pip --version` (look for `(python 3.12)`).
- No virtual environments are used (project preference).

Stack confirmed working in 3.12 (2026-05-24): torch 2.6.0+cu124 (CUDA True on RTX 4090 Laptop), transformers, peft, trl, bitsandbytes, accelerate, datasets, pandas. Driver NVIDIA 595.71.05, supports up to CUDA 13.2; torch cu124 wheels run fine via forward-compat.

---

## 3. Current State (as of 2026-05-24)

### What survived the reinstall / what was lost

- **LOST:** the original v3 adapter (`model-output-v3/`) and the exact v3 dataset. Both were gitignored (`model-output*/`, `train.jsonl`, `eval.jsonl`), so neither was in the repo. **The original 91%-accuracy v3 is NOT recoverable bit-for-bit.**
- **SURVIVED (in Git):** all scripts (`parse_dataset.py`, `finetune.py`, `test_model.py`), `csic_database.csv`, `README.md`, `CONTEXT.md`.
- **PRESENT on disk:** `~/PayloadsAllTheThings/` (re-cloned — newer version, see §6), stale local `train.jsonl`/`eval.jsonl` of 13,692 lines (NOT the v3 dataset — overwritten on 2026-05-24 regeneration).

### Model Versions

| Version | Location | Status |
|---------|----------|--------|
| v1, v2 | old `model-output*/` dirs | Lost in reinstall (gitignored) |
| v3 (original) | gone | Lost; reported ~91% acc, not reproducible bit-for-bit |
| **v3-rebuild** | `~/Desktop/firewall-IA/model-output-v3/` | **DOES NOT EXIST ON DISK** (verified 2026-08-16). Not trained. |

**CORRECTION (2026-08-16 audit): there is currently NO trained model anywhere in this project.** `model-output-v3/` is absent from disk. `finetune.py` has never successfully run on the current machine, and cannot (see §12, F4). `classifier_api.py` and `test_model.py` both fail at load time because `ADAPTER_DIR` does not exist.

**Consequence: the project has NO current experimental baseline.** The roadmap has not reached the end of V3.

### Status of the historical ~91% result

The ~91% / "0 false positives" figure from the original v3 is **historical context only. It is NOT the current baseline and must never be used as a comparison point for v4.** Reasons:

- The adapter and its exact dataset were lost in the reinstall; the result is not reproducible bit-for-bit.
- It was measured on a suite of 135 cases that is **109 BLOCK / 26 ALLOW**. A degenerate always-BLOCK classifier scores 80.7% on that suite, so 91% is +10.3 pp over the majority class — not +41 pp over chance.
- "0 false positives" was measured on **n = 26** ALLOW cases. By the rule of three the 95% upper bound on the true FPR is ≈ 11%. It is not a safety claim.
- Per-category accuracy was computed over 5 cases per category, i.e. 20 pp resolution. The reported "CSRF 40%" is literally 2 of 5.

Per **D7**, scientific validity takes priority over preserving this number. A clean baseline is expected to score lower, and that is an accepted outcome.

### Dataset — regenerated 2026-05-24 (the new baseline)

| Split | Path | Lines |
|-------|------|------:|
| Train | `~/Desktop/firewall-IA/train.jsonl` | 79,305 |
| Eval  | `~/Desktop/firewall-IA/eval.jsonl`  | 19,827 |
| **Total** | | **99,132** |

BLOCK: 49,566 | ALLOW: 49,566 | exact 1:1 balance.

**Paths are now unified to `~/Desktop/firewall-IA/`** in all three scripts (previously split between `~/ai-firewall/` and the project dir — fixed this session). `parse_dataset.py` OUTPUT, `finetune.py` TRAIN/EVAL, and `test_model.py` EVAL all point to `~/Desktop/firewall-IA/`.

### Why the dataset nearly doubled (52K → 99K) — CORRECTED 2026-08-16

The previous 52,670 dataset was silently **missing Path Traversal and CSRF** because `parse_dataset.py` looked for folder names that no longer exist in the current PayloadsAllTheThings (see §6). Fixing the two folder-name keys added ~46,000 examples.

> **⚠️ CORRECTION — the earlier claim in this section was FALSE.**
>
> This section previously said the ~46,000 increase came from "those two categories" and concluded that "add those categories is DONE". **That is wrong.** Measured directly against the generated `train.jsonl` + `eval.jsonl` on 2026-08-16:
>
> | Category | Examples | % of 99,132 |
> |----------|---------:|------------:|
> | Path traversal | **24,176** | 24.39% |
> | File inclusion | 8,447 | 8.52% |
> | **CSRF** | **46** | **0.05%** |
>
> The increase came **predominantly from Directory Traversal and related file-path data**. **CSRF contributed 46 examples.**
>
> **CSRF is NOT fixed. It remains, by this project's own reasoning, essentially untrained.** The v3 observation that "a model cannot be blamed for failing a category it never saw" still applies to CSRF today.
>
> The same applies to every other low-volume category — see the full per-category table in §11.

Run `python3.12 check_dataset.py` to re-measure this at any time. Do not restate category coverage from memory.

### Data Sources

1. **PayloadsAllTheThings** (`~/PayloadsAllTheThings/`) — `.md` code blocks + heuristic lines + `.txt` payload files across **16** active category directories (now includes Directory Traversal + Cross-Site Request Forgery).
2. **Hardcoded payloads** (in `parse_dataset.py`) — CRLF (240 wrapped), HPP (400), XPath (280).
3. **Synthetic LEGIT_REQUESTS templates** (in `parse_dataset.py`) — REST API, auth, mobile, GraphQL, webhook, false-positive mitigations; multiplied then trimmed.
4. **CSIC 2010 HTTP dataset** (`csic_database.csv`) — 61,065 real requests from a Spanish e-commerce app; 36,000 Normal (ALLOW) + 6,587 Anomalous included as BLOCK (18,478 generic-fallback excluded as noise).

### Attack Categories Covered — 19 total

From PayloadsAllTheThings (16):
SQL Injection, XSS Injection, **Directory Traversal**, Command Injection, LDAP Injection, XXE Injection, **Cross-Site Request Forgery**, Open Redirect, Server Side Request Forgery, JSON Web Token, GraphQL Injection, NoSQL Injection, Server Side Template Injection, File Inclusion, Insecure Deserialization, Request Smuggling.

Hardcoded (3): CRLF Injection, HTTP Parameter Pollution, XPath Injection.

**No category directory was SKIPPED in the 2026-05-24 run** — but "not skipped" does not mean "adequately covered". See the corrected volumes above and in §11.

---

## 4. Dataset imbalance — CONFIRMED 2026-08-16 (was: "suspected")

The 1:1 balance is BLOCK-vs-ALLOW **globally only**. Within the BLOCK pool the distribution is severely skewed. This was previously recorded as a hypothesis to test with `test_model.py`; it can be settled at the dataset level with **no model at all**, and it has been:

- **Path traversal 24,176 vs CSRF 46 — a 525:1 ratio.**
- Six categories are below 0.25% of the dataset: Request Smuggling (52), CSRF (46), GraphQL (118), LDAP (123), NoSQL (135), JWT (196).
- Within CSIC, SQL injection dominates the anomalous pool and is low-diversity (mostly the same `DROP TABLE usuarios` payload in the `cantidad` param of the same JSP endpoint).

The final 1:1 random trim (seed=42) did **not** mitigate this — it only balances BLOCK against ALLOW.

**Per-category rebalancing is a required task for the clean dataset**, not just BLOCK/ALLOW balancing. Note that any per-category accuracy claim also requires expanding `test_model.py` beyond 5 cases/category (20 pp resolution is not a measurement).

---

## 5. The API (built this session by Claude Code)

`classifier_api.py` — a FastAPI service wrapping the v3 model as the **classification engine (control plane)**. A future proxy (data plane) will consume it. Status: **built, not yet validated** (no adapter existed when built).

- Adapter path is configurable: `ADAPTER_DIR = os.path.expanduser(os.environ.get("FIREWALL_ADAPTER_DIR", "~/Desktop/firewall-IA/model-output-v3"))`. Set `FIREWALL_ADAPTER_DIR` to point at different model versions without editing code.
- Replicates `test_model.py` inference EXACTLY: same prompt template, same generation params (`max_new_tokens=40`, `do_sample=False`, `eos_token_id=end_token_id`), same extraction regex.
- Endpoints: `POST /classify` (body `{"request": "<raw HTTP text>"}` → `{decision, reason, raw_output, latency_ms}`) and `GET /health`.
- Input is RAW HTTP TEXT, never structured fields — the model was trained on raw text.
- GPU concurrency: `generate` must be serialized (asyncio.Lock or single worker) so concurrent requests don't corrupt inference.
- **Validation step pending:** once the adapter exists, run the API and confirm its decisions match `test_model.py` on the same requests.

---

## 6. PayloadsAllTheThings folder renames (root cause of missing categories)

The re-cloned repo renamed directories. `parse_dataset.py` CATEGORIES keys were updated this session:
- `"Path Traversal"` → `"Directory Traversal"` (NOT `Client Side Path Traversal`, which is a different, client-side attack — do not map to it).
- `"CSRF Injection"` → `"Cross-Site Request Forgery"`.

Output labels (the values, e.g. `"BLOCK | Path traversal attack detected."`) were left unchanged so they still match the test-suite expectations. Only the folder-name keys changed.

**Process lesson:** `[SKIP] Carpeta no encontrada` is currently SILENT — the script continues with missing categories. Treat `[SKIP]` as an ERROR, not a warning. A v4 improvement: make the script fail loudly (or at least summarize skipped categories prominently) if an expected folder is absent.

**Reproducibility — PayloadsAllTheThings commit RECORDED (2026-08-16):**

```
e961fef231d8327bae83b563fab50aec2e6b77c0
```

This is the commit present at `~/PayloadsAllTheThings/` when the current 99,132-example dataset was generated. Any regeneration intended to reproduce that dataset must check out this commit first. Re-verify with `git -C ~/PayloadsAllTheThings rev-parse HEAD`.

**Caveat — recording the commit is necessary but NOT sufficient for reproducibility.** `parse_dataset.py` is non-deterministic despite `random.seed(42)`, because the random stream's consumption order depends on `list(set(payloads))` (set iteration over strings varies with `PYTHONHASHSEED`, randomised per process) and on unsorted `os.listdir()` / `os.walk()` ordering. Two runs on this same machine at this same PATT commit will produce **different** datasets. Determinism is part of the D6 work.

---

## 7. v4 Plan — SUPERSEDED 2026-08-16

> **⚠️ The v4 plan recorded here was built on two premises that the audit disproved.**
>
> 1. *"Baseline already includes Path Traversal + CSRF … so 'add those categories' is DONE."* — **False.** CSRF has 46 examples (§3). It is not done.
> 2. *"Group 2: strengthen weak categories — JWT and GraphQL (genuinely weak, unlike CSRF which was just absent)."* — **The CSRF/JWT distinction does not hold.** CSRF (46), Request Smuggling (52), GraphQL (118), LDAP (123), NoSQL (135) and JWT (196) are all in the same low-volume regime. None of them is "genuinely weak" as opposed to "absent" — all are under-represented.
>
> There is also **no v3-rebuild baseline to measure against** (§3), so "trained+measured against the v3-rebuild baseline" is not currently executable.

Retained as still-valid from the original plan:

- **Remove `###END###`** (now **D5**, approved). Redundant — the inference regex already cuts on `.`/EOL, and TinyLlama's native `</s>` is the real stop token. Edit 3 files: `parse_dataset.py` (strip from INSTRUCTION + all outputs), `finetune.py` (remove `add_special_tokens` / `resize_token_embeddings`), `test_model.py` (simplify regex, drop `eos_token_id`). **Note:** the earlier characterisation of this as a mere "design-cleanliness change" understated it — see §12 F5, the token is structurally untrainable under the current LoRA config. But per **D5**, *do not claim a measured before/after latency improvement* unless a controlled experiment is later run; the historical v3 no longer exists to compare against.
- **Per-category rebalancing** — now confirmed necessary (§4), and broader than "JWT and GraphQL".
- **CSIC envelope bias fix** — subsuming into **D1** (shared envelope distributions across both classes), which is a stronger and more general fix.

**The current plan is the ordered experiment sequence in §13.** Do not restart v4 from this section.

---

## 8. Data strategy — proxy as a data factory (future)

Rather than sourcing a generic benign-traffic dataset (would carry its own app/era biases, same problem as CSIC), the stronger plan is to **capture realistic traffic via the proxy** once built. Validated in recent literature (capture via local proxy + Burp Logger, label as normal/attack).

Plan: put the proxy in front of a controlled app (DVWA / bWAPP, or a real app), browse legitimately → capture ALLOW; launch known attacks → capture BLOCK. **Same envelope for both ALLOW and BLOCK breaks the CSIC envelope bias at the root** — the model can no longer use User-Agent/cookies as a shortcut and must learn the payload. Labeling is reliable because the source is controlled. This is post-baseline, post-proxy work.

The weakest part of the current dataset is **legitimate-traffic diversity** (synthetic LEGIT_REQUESTS + 2010 CSIC normals), not attack diversity. Proxy capture directly addresses this.

---

## 9. Files and What They Do

### `parse_dataset.py`
Generates train/eval JSONL. Run `python3.12 parse_dataset.py`.
- `build_dataset()` — payloads from PayloadsAllTheThings + hardcoded categories + synthetic ALLOW pool.
- `build_obfuscated_examples(raw_block_payloads, 2000)` — 8 obfuscation transforms → 2,000 obfuscated BLOCK variants.
- `categorize_csic_anomalous(request_str)` — 11-rule heuristic on raw + `unquote_plus()`-decoded string.
- `integrate_csic2010(filepath)` — reconstructs HTTP requests from CSV (host→`target.com`, strips `/tienda1`), routes Normal→ALLOW, Anomalous→BLOCK (generic fallback filtered out).
- `main()` — build → obfuscate → integrate CSIC → merge → rebalance 1:1 (min-trim, seed=42) → shuffle → split 80/20 → write.

### `finetune.py`
LoRA fine-tune (4-bit NF4, rank=16, alpha=32). Run `python3.12 finetune.py`.
- `TRAIN_FILE`/`EVAL_FILE` → `~/Desktop/firewall-IA/`; `OUTPUT_DIR = model-output-v3` (already set).
- `resume_from_checkpoint=False` (set this session — fresh machine has no checkpoint to resume; `True` would crash).
- 4 epochs, batch 4, grad accum 8, lr 2e-4 cosine, **BF16 (D11)**, paged_adamw_8bit. Eval and save every 200 steps, `save_total_limit=2` (**D12**). `SFTConfig` + `SFTTrainer`.
- **Ported 2026-08-17 (E1) and verified running** — `SFTConfig`, `processing_class=`, `max_length=512`. See §12 F3 and `reports/e1_training_pipeline_smoke.txt`.
- `--smoke` runs a bounded compatibility test (500/100 examples, 12 steps, separate `model-output-e1-smoke/`). `--force-fp16` reproduces the pre-D11 incompatibility.
- **`###END###` removed 2026-08-17 (E4/D5).** No `add_special_tokens`, no `resize_token_embeddings`; termination is native EOS. See §12 F5 and `reports/e4_remove_end_token.txt`.

### `test_model.py`
Loads base TinyLlama + LoRA from `model-output-v3`. Runs SYSTEMATIC (5×19 categories) + ADVERSARIAL (20) + FALSE_POSITIVE (20) suites; prints per-category accuracy, false positives/negatives, failures, and a 100-sample latency benchmark.
- Greedy decode, max 40 new tokens, regex `\b(ALLOW|BLOCK)\b\s*\|\s*(.+?)\s*(?:\.|\n|$)` — byte-identical to `classifier_api.py` (E4).
- **Suite composition (measured): 135 cases = 109 BLOCK / 26 ALLOW, 21 category labels.** Always-BLOCK scores 80.7%. The 26 ALLOW cases are too few to support any false-positive-rate claim.
- **⚠️ CORRECTION:** this file previously recorded "token handling is correct, no latent bug." **That is wrong** — `resize_token_embeddings` adds a randomly-initialised row that the LoRA config never trains and never saves, and it is re-randomised on every load. See §12 F5.
- Metric set is inadequate: accuracy / FP count / FN count only. No precision, recall, F1, FPR, FNR, or confusion matrix. Latency reports mean/min/max/stdev/median — **no P95, no P99**, which D3 requires.

### `check_dataset.py`  *(added 2026-08-16 — experiment E0)*
**Dataset integrity gate. Analysis-only — never mutates the dataset.** Run `python3.12 check_dataset.py`.
Measures, from the JSONL files each run (nothing hardcoded): per-category counts, duplication, exact train→eval leakage, envelope-confound distributions, trivial single-feature baselines, and SHA-256 hashes of all inputs. Exits `PASS` / `WARNING` / `FAIL`.
**Gate rule: no training run starts while this reports FAIL.**

### `csic_database.csv`
CSIC 2010. 61,065 rows × 17 cols. Label col `Unnamed: 0` (`"Normal"`/`"Anomalous"`). Used: `Method`, `URL`, `User-Agent`, `cookie`, `content-type`, `content`. `URL` cell format: `http://localhost:8080/tienda1/path?query HTTP/1.1`. Col `lenght` is an original-data typo.

---

## 10. Known Limitations and Intentional Decisions

- **CSIC User-Agent bias (still present):** all CSIC examples use the same Konqueror UA + JSESSIONID pattern. Fix is **D1** (shared envelope distributions) + proxy capture (§8).
- **18,478 CSIC Anomalous excluded:** structural anomalies (buffer overflow, integer tampering, cookie poisoning) with no keyword-detectable payload; generic label can't be validated from content. ~73.7% of CSIC Anomalous. **Per D2, these stay excluded from the clean baseline** and are preserved conceptually as a separate future experimental dataset.
- **CSIC attack diversity is narrow:** ~70% SQL, low payload variety (see §4).
- **`--` SQL keyword rule is broad** in `categorize_csic_anomalous()`; acceptable for e-commerce context, revisit if extended.
- **Latency: the ~800ms/request figure is UNVERIFIED and confounded.** No model exists to measure. It was also inflated by forced 40-token generation (§12 F5), so it was never a measure of decision latency. **Per D3 the design target is now defined: end-to-end added latency P95 ≤ 200 ms** — a target, not a demonstrated capability. Future measurement must decompose into model-only / model+API / proxy overhead / end-to-end, each with P50, P95, P99 and throughput.
- **Failure behaviour: FAIL-CLOSED** per **D4**. If the classifier times out, crashes, is unavailable, or returns an invalid decision, traffic is blocked by default. A fallback mechanism is explicitly out of current scope.

---

## 11. Measured dataset composition (2026-08-16)

Measured directly from `train.jsonl` + `eval.jsonl` (99,132 examples). **Re-measure with `check_dataset.py`; do not quote these from memory after the dataset is regenerated.**

| Label | Count | % |
|-------|------:|--:|
| ALLOW | 49,566 | 50.00 |
| BLOCK — Path traversal | 24,176 | 24.39 |
| BLOCK — File inclusion | 8,447 | 8.52 |
| BLOCK — SQL injection | 7,040 | 7.10 |
| BLOCK — Cross-site scripting | 4,124 | 4.16 |
| BLOCK — Command injection | 1,469 | 1.48 |
| BLOCK — CRLF injection | 744 | 0.75 |
| BLOCK — SSTI | 697 | 0.70 |
| BLOCK — Insecure deserialization | 414 | 0.42 |
| BLOCK — HPP | 400 | 0.40 |
| BLOCK — Open redirect | 391 | 0.39 |
| BLOCK — XXE | 381 | 0.38 |
| BLOCK — SSRF | 312 | 0.31 |
| BLOCK — XPath | 301 | 0.30 |
| BLOCK — JWT | 196 | 0.20 |
| BLOCK — NoSQL | 135 | 0.14 |
| BLOCK — LDAP | 123 | 0.12 |
| BLOCK — GraphQL | 118 | 0.12 |
| BLOCK — Request smuggling | 52 | 0.05 |
| **BLOCK — CSRF** | **46** | **0.05** |

**ALLOW pool diversity (measured):** 49,566 ALLOW examples contain only **23,516 unique inputs**. Of these, the synthetic side is 26,290 examples drawn from just **240 unique strings** (≈110× replication); the remaining 23,276 are CSIC normals, all from one 2010 Spanish e-commerce app with one host, one User-Agent and one cookie pattern. Benign diversity is the weakest part of the dataset — §8 already says this; the measurement is worse than the prose implied.

---

## 12. Audit findings — 2026-08-16

Full audit: `reports/` (see also the standalone audit document produced 2026-08-16). Finding IDs are referenced throughout this file.

### F1 — CRITICAL — the `Host` header is a near-perfect label shortcut

Measured `Host` → label mapping across all 99,132 examples:

| Host | Total | ALLOW | BLOCK |
|------|------:|------:|------:|
| `target.internal.com` (all PayloadsAllTheThings + hardcoded + obfuscated) | 42,979 | **0** | 42,979 |
| `target.com` (all CSIC) | 29,863 | 23,276 | 6,587 |
| 53 other hosts (all synthetic LEGIT_REQUESTS) | 26,290 | **26,290** | **0** |

A classifier that reads **only the `Host` header** and never the payload scores **≈93% on this dataset — higher than the historical 91% attributed to the model.** `wrap_in_http()` hardcodes `target.internal.com` on every attack example; the synthetic benign templates use `example.com`-family hosts exclusively; CSIC uses `target.com`.

**Consequence: every accuracy number produced on this dataset is uninterpretable as evidence of attack detection.** Training loss can be minimised almost entirely from the `Host` token.

**`Host` is not the only shortcut.** The E0 gate run of 2026-08-16 (`reports/e0_dataset_integrity_current.txt`) scored every single non-payload feature by fitting a lookup table on train and evaluating on eval. Majority-class baseline is 49.91%:

| Non-payload feature alone | Eval accuracy | vs majority |
|---------------------------|--------------:|------------:|
| `Host` value | **93.72%** | +43.81 |
| `Content-Type` value | **82.62%** | +32.72 |
| Header-name set (structural fingerprint) | 76.84% | +26.94 |
| Header count | 75.88% | +25.97 |
| Body present/absent | 74.12% | +24.21 |
| HTTP method | 74.06% | +24.15 |
| `User-Agent` value / presence | 67.94% | +18.03 |
| `Cookie` presence | 67.14% | +17.23 |

**Every one of these is an independent shortcut**, and they are structural, not incidental:
- **HTTP method** — `wrap_in_http()` picks a random method for attack examples, so DELETE (90.8%), PATCH (92.9%) and PUT (91.8%) are near-pure BLOCK, while the synthetic benign templates are mostly GET/POST.
- **Content-Type / body / header-count / header-set** — a direct consequence of the three sources emitting three fixed request shapes: PayloadsAllTheThings wraps are `host` + optional `content-type`; CSIC always carries `cookie` + `user-agent`; synthetic ALLOW carries assorted realistic headers.
- **Malformed request-target** — a raw space inside the request-target appears in 1,418 BLOCK examples and **0 ALLOW** (100% pure). Cause: `wrap_in_http` interpolates raw scraped lines into `GET {path}?{param}={payload} HTTP/1.1` without percent-encoding.

**Implication for D1:** neutralizing `Host`, `User-Agent` and cookies is necessary but **not sufficient**. Method, body presence, `Content-Type`, and the header-name set must also be drawn from shared distributions across both classes, and payloads must be percent-encoded into the request-target. D1's "and similar metadata" clause is doing real work here — treat this table as its concrete scope.

**Nine deterministic label reveals** were flagged (a single envelope value ≥99% pure over ≥1% of the dataset): `target.internal.com`→BLOCK (43.36% of the dataset), seven `*.example.com`-family hosts→ALLOW, and the malformed-target artifact→BLOCK.

Re-measure with `check_dataset.py` after any regeneration. Do not quote this table once the dataset changes.

### F2 — CRITICAL — 26.6% train/eval leakage

Measured: **5,283 of 19,827 `eval.jsonl` inputs appear verbatim in `train.jsonl` (26.65%).** Unique inputs are 73.76% of train and 74.63% of eval — i.e. each split is also ~26% internally duplicated.

**The leakage is concentrated in just 253 distinct strings** (E0 run, 2026-08-16) — a handful of templates replicated hundreds of times. The single worst appears 171× in train and 39× in eval. This confirms the mechanism: it is template replication, not broad overlap.

Cause: `main()` shuffles and splits a pool that already contains exact duplicates (240 `LEGIT_REQUESTS` replicated ~110×; CRLF/XPath emit 8 wraps per payload; HPP is templated; obfuscated examples derive from payloads already in the base pool). There is no deduplication step anywhere in `parse_dataset.py`.

**Consequence:** `finetune.py` sets `load_best_model_at_end=True`, with `metric_for_best_model` defaulting to `eval_loss`. **Model selection is performed on a leaked validation set, so it rewards memorisation.**

The fix must dedup *and* split on a payload-identity key, so that obfuscated/wrapped variants of one payload cannot straddle the split.

### F3 — RESOLVED 2026-08-17 (E1) — `finetune.py` could not run on the installed stack

> **Resolved.** Ported to `SFTConfig` / `processing_class` / `max_length`; smoke test PASS. See `reports/e1_training_pipeline_smoke.txt`.
>
> **One recipe-affecting change was forced, now ratified as D11:** `fp16=True` → `bf16=True`. TRL 1.4 casts all trainable params to bfloat16 when the base model is 4-bit loaded (`sft_trainer.py:1088-1092`), and `fp16` routes through `GradScaler`, whose `_amp_foreach_non_finite_check_and_unscale_cuda` kernel has no BFloat16 implementation. fp16 + 4-bit QLoRA cannot run on TRL 1.4 at all. `python3.12 finetune.py --smoke --force-fp16` reproduces the crash. **D11 is a compatibility decision and must never be presented as a model-quality improvement** — no fp16-vs-bf16 quality comparison exists or can be made.
>
> **Also confirmed quantitatively, now ratified as D12:** the production recipe (4 epochs, `save_steps=200`, no `save_total_limit`) would produce ~49 checkpoints at ~302 MB each ≈ **14.8 GB before optimizer state**. `save_total_limit=2` is now set; `save_steps` and all other hyperparameters are unchanged.
>
> Original finding preserved below.

Installed and verified 2026-08-16: `transformers 5.8.0`, `trl 1.4.0`, `peft 0.19.1`, `torch 2.6.0+cu124`, `bitsandbytes 0.49.2`, `accelerate 1.13.0`, `datasets 4.8.5`.

Verified by introspecting `trl.SFTTrainer.__init__` on this machine — `dataset_text_field`, `max_seq_length` and `tokenizer` are **all rejected**. They moved onto `SFTConfig` / `processing_class`. `transformers.Trainer` also no longer accepts `tokenizer=`.

`finetune.py` passes all three. **Training is blocked until this is ported.** Environment drift, not a design flaw. There is no `requirements.txt` or lockfile anywhere in the repo, so further drift is likely.

*(Numbered F4 in the original audit document; renumbered here. The audit's F3 — benign diversity — is recorded in §11.)*

### F5 — RESOLVED 2026-08-17 (E4) — `###END###` was structurally untrainable

`finetune.py` adds `###END###` as a special token and calls `resize_token_embeddings`, appending a **randomly initialised** row to `embed_tokens` and `lm_head`. `LoraConfig.target_modules` covers only `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj` — **`embed_tokens` and `lm_head` are in neither `target_modules` nor `modules_to_save`.** Therefore:

1. The new token's embedding and output-head row receive no gradient.
2. `generate(..., eos_token_id=end_token_id)` therefore almost certainly never fires — every inference runs the full `max_new_tokens=40`.

> **⚠️ CORRECTED 2026-08-17 by E1 measurement** (`reports/e1_training_pipeline_smoke.txt` §7a). Two parts of the original finding were wrong on this stack:
>
> - **"randomly initialised"** — wrong. transformers 5.8 mean-resizes new rows from a multivariate normal fitted to the existing embeddings' mean and covariance.
> - **"never saved / re-randomised on every load"** — wrong. PEFT force-saves **both full embedding matrices** when it detects a resize (`peft/utils/save_and_load.py:386`), so the row is persisted and deterministic across loads.
> - **"receives no gradient"** — **correct, and confirmed.** The saved `adapter_config.json` has `modules_to_save=None` and `trainable_token_indices=None`. The token is saved at its initialisation value and never learns to be emitted.
>
> **The strongest argument for D5 is now a measured cost, not load non-determinism:** the resize inflates the saved adapter from ~24 MiB (LoRA only, 12,615,680 params) to **298 MB**, because 131,076,096 params of full `embed_tokens` + `lm_head` matrices are written into every checkpoint and into the final adapter — carrying no trained information beyond the base model. **A ~12× size increase.** This bears directly on D8 item 3 (GGUF export) and D10 (embedded storage budget).
>
> TRL 1.4 has machinery that would fix this class of bug (`trainable_token_indices` + automatic `modules_to_save=["lm_head"]`), but it only fires for tokens TRL itself adds via chat-template cloning — not for tokens added externally as `finetune.py` does.

**RESOLVED 2026-08-17 by E4.** The token, the `add_special_tokens` call and the `resize_token_embeddings` call are gone from all four pipeline files; termination is native EOS (`</s>`, id 2). Verified without training: tokenizer vocabulary stays at 32,000, and the saved adapter contains **no** `embed_tokens`/`lm_head` tensors — 12,615,680 params total. The structural cause of the ~12× inflation is removed. **No latency improvement is claimed**; that remains a hypothesis until measured.

### F6 — HIGH — CSIC BLOCK labels are produced by the mechanism a rule-based baseline would use

`categorize_csic_anomalous()` assigns every CSIC BLOCK label with an 11-rule keyword heuristic, and **discards the 18,478 rows (73.7% of CSIC Anomalous) it cannot match**. The CSIC attack set is therefore, by construction, exactly the subset a keyword matcher detects.

This makes any future rule-vs-AI comparison circular on the CSIC portion. Per **D9** that comparison is future/optional work, so this is not currently blocking — but it must be addressed before any such comparison is attempted. Per **D2** the excluded rows are preserved as a separate future experimental dataset, which is precisely the portion where an AI classifier could plausibly show an advantage over a regex.

### F7 — HIGH — label noise from the markdown scraper

`extract_payloads_from_md()` has a second pass that accepts **any** line in a file (not only fenced code) containing one of `'` `"` `--` `;` `|` `UNION` `SELECT` `DROP` `<script` `../` `&&` `||` `$(` `` ` `` at 10–300 chars. English prose, markdown table rows and reference URLs all match. The `.txt` walk accepts every line over 3 characters.

Observed in the generated dataset:

```
GET /admin/query?data=var xhr = new XMLHttpRequest(); HTTP/1.1   → BLOCK | CSRF
GET /admin/query?search=&#x00003C HTTP/1.1                       → BLOCK | XSS
POST /admin/query … cmd=//..\/..\/..\/..\/..\{FILE}              → BLOCK | Path traversal
```

The last contains an **unresolved fuzzer template placeholder** `{FILE}`. The 24,176 path-traversal examples are largely raw fuzzing-wordlist entries, not HTTP requests.

### F8 — HIGH — obfuscation is not an independent generalization test

`build_obfuscated_examples()` samples from `raw_block_payloads`, the same pool used to build the base BLOCK examples — so the un-obfuscated original of nearly every obfuscated example is also in the dataset. The 20 `ADVERSARIAL_CASES` in `test_model.py` use the same transform families seen in training. **The adversarial suite is in-distribution**: it measures whether the model learned its 8 training transforms, not evasion resistance. A real evaluation needs held-out transforms and held-out base payloads.

### F9 — MEDIUM — generated JSONL are tracked in Git despite documentation saying otherwise

`.gitignore` lists `train.jsonl` and `eval.jsonl`, and earlier revisions of this file stated that generated datasets are "not versioned". **Both files are in fact tracked** (`git ls-files` confirms), totalling ~43.5 MB of JSONL committed without Git LFS (`.gitattributes` contains only `* text=auto`). `.gitignore` has no effect on already-tracked files.

This is currently the *only* reason the 99,132-example dataset still exists, so it is load-bearing historical evidence. **Per D6, do NOT `git rm --cached` these files yet** — the migration procedure must be documented and proposed first so historical evidence is not lost.

### Other findings carried forward

- **Non-deterministic generation** despite `seed=42` — see §6.
- **Silent `[SKIP]`** in `build_dataset()` is still armed (§6) — the exact failure that cost v3 two categories.
- **Unbounded checkpointing:** `save_steps=200` with `save_total_limit` unset ≈ 49 checkpoints (adapter + `paged_adamw_8bit` state) — disk-exhaustion risk on a laptop.
- **Test-suite contamination:** 1 of 135 cases appears verbatim in `train.jsonl`; 11 of 135 test payload *fragments* appear verbatim inside training text (~8%). Tolerable if disclosed; currently undisclosed.
- **Reason labels are folder-determined, not content-determined** — a payload in two PayloadsAllTheThings directories gets two different BLOCK reason strings.
- **Accidental partial ablation:** 110 of 136 `Host:` lines in `test_model.py` use `target.com` — the envelope where the F1 shortcut argues *against* blocking. If the lost v3 genuinely scored 91% there, that is weak evidence it learned something beyond the envelope. Unconfirmable now (no model), and an accident of test authorship rather than a designed control.

---

## 12b. Candidate clean dataset (v4) — E2 + E3, 2026-08-17

**Status: CANDIDATE. Not a validated baseline.** E0 returns WARNING (no blocking failures).
It must be reviewed before any training run. Full report: `reports/e2_e3_clean_dataset.txt`.

- Generator: **`parse_dataset_v4.py`** (new file). `parse_dataset.py` is left untouched and executable — it is the control condition for the E2 before/after comparison.
- Artifacts: `datasets/v4_clean/{train,eval}.jsonl` — **25,134 / 6,206 rows** (31,340 total), eval ratio 0.1980, exactly 1:1 ALLOW/BLOCK. Generated under **D17 FINAL** (policy B · group cap 2,500 · row cap 4,000).
- Evidence trail preserved: `reports/e2_e3_clean_dataset_uncapped.txt`, `reports/e0_dataset_integrity_v4_clean_uncapped.txt`, `datasets/manifest_v4_clean_uncapped.json`, plus the two sensitivity analyses that selected the final policy — `reports/e2_e3_cap_sensitivity.txt` and `reports/e2_e3_row_cap_sensitivity.txt`. Every scenario is exactly reproducible from the generator flags.

### D17 FINAL — two independent contribution levers

The finalized methodology distinguishes **two different quantities** that were previously conflated:

| Lever | Setting | Applied | Controls |
|---|---|---|---|
| Cap policy | **B — source-agnostic** | — | CSIC-derived BLOCK groups count toward the same per-category budget as PayloadsAllTheThings/hardcoded |
| **Logical-group cap** | **2,500 / malicious category** | *before* rendering | **source/category DIVERSITY dominance** — how many distinct source payloads a category may contribute |
| **Rendered-row cap** | **4,000 BLOCK rows / malicious category** | *after* rendering + dedup, *before* balancing | **final training CONTRIBUTION** — how much a category actually contributes to training |

**Both are required.** A group cap alone cannot control contribution: a CSIC group is a request *shape* that collapsed many original records, and every record still renders. Measured at a 2,500-group cap, SQL Injection still produced 5,545 rows while Path Traversal produced 2,511 — a group cap cannot reach that redundancy.

**Row selection** is deterministic, source-stratified (proportional by largest remainder, so neither PayloadsAllTheThings nor CSIC is deleted first), and **breadth-first** — one row per logical group before any second row. It therefore spends the budget on breadth before depth and removes redundant *renderings* before it removes logical *diversity*. Measured at the final settings: SQL Injection 5,545 → 4,000 rows at **100% logical-group retention**, and 100% retention in every other category.

**Hard floor, enforced in code:** `row_cap ≥ group_cap`. Below it, retention pins at exactly `row_cap/group_cap` by arithmetic (measured: 2000/2500 → 80.0% in four categories). The generator now refuses to run rather than silently destroying diversity.

> **25.5% largest-category share is an observed outcome of this compromise, not a target or a standard.** Do not cite it as a balance threshold.
- Manifest: `datasets/manifest_v4_clean.json` (SHA-256, counts, rejection reasons, limitations).
- The historical `train.jsonl` / `eval.jsonl` at repo root are **unchanged**.

### What E0 measures on it

| Metric | Historical | Candidate |
|---|---:|---:|
| E0 verdict | FAIL | WARNING |
| train→eval leakage | 26.65% | **0.00%** |
| within-split duplicates | 26.24% / 25.37% | **0.00% / 0.00%** |
| deterministic label reveals | 9 | **0** |
| `Host` baseline | 93.72% | **49.73%** |
| `Content-Type` baseline | 82.62% | 51.16% |
| header-name set | 76.84% | 49.21% |
| header count | 75.88% | 49.89% |
| body presence | 74.12% | 50.00% |
| HTTP method | 74.06% | 50.00% |
| User-Agent (value) | 67.94% | 50.47% |
| User-Agent (presence) | 67.94% | 49.76% |
| Cookie presence | 67.14% | 49.65% |
| majority baseline | 49.91% | 50.00% |

Eight of eleven incidental features sit **at or below** the majority baseline; the strongest is Content-Type at +1.16. **On this dataset no incidental envelope feature beats a coin flip.** This is a statement about the dataset only — no model has been trained on it.

### How (structural, not shortcut-by-shortcut)

1. **One shared envelope generator** for both classes — no benign-only or attack-only host, UA or cookie exists anywhere. CSIC records are re-rendered under it (semantics preserved, envelope redrawn), which kills the `target.com` + Konqueror signature.
2. **Shape matching** — 15 request "shapes" (method set, paths, params, content type, special headers). Every attack shape gets benign traffic in the *same* shape at *matched volume*. This collapsed Content-Type, header-set, header-count and body-presence simultaneously.
3. **Method-stratified class balancing** — within each HTTP method both classes are trimmed to the minimum, forcing `P(BLOCK | method) = 0.5`. Trimming only; nothing duplicated.

### Causal exceptions (deliberately allowed to correlate)

Measured: Origin **presence** 54.8% pure (non-predictive, because benign counterparts carry same-origin Origin/Referer), but Origin **cross-origin** 100% BLOCK — that relationship *is* the CSRF attack. Same pattern for smuggling framing headers and HPP duplicate parameters. All documented in the manifest under `causal_envelope_exceptions`.

### Reproducibility

Two consecutive runs with `PYTHONHASHSEED=random` produced **bit-identical** output — the historical generator could not do this. Sorted traversal, no set-iteration dependence, per-sample RNG seeded from group id, deterministic hash-bucket split.

### D17 FINAL — what the caps did

Group cap 2,500 (policy B, merged PATT+CSIC pool): Directory Traversal 10,218→2,500, SQL Injection 2,953→2,500, File Inclusion 2,937→2,500, XSS 2,628→2,500. Row cap 4,000: only SQL Injection exceeded it — **5,545 → 4,000 rows at 100% logical-group retention (2,500 → 2,500)**.

Largest attack-category share of BLOCK: **47.3% → 25.5%**. Top-3 combined 70.6% → 65.2%. Effective category count 6.36 → 7.42. Rows per represented logical group now 1.00–1.67 in every category — the redundancy that made row counts a misleading diversity proxy is gone.

Policy A was retired because it could not control dominance at any cap (SQL never fell below 36.5% of BLOCK) and cap1000_A was Pareto-dominated — smaller *and* more dominated than the policy-B alternatives. See `reports/e2_e3_cap_sensitivity.txt`.

CSIC BLOCK traffic retained: 3,906 of 5,900 rows (66%). This is the price paid for contribution control, and it is real: CSIC is the only non-synthetic attack traffic in the dataset.

### ⚠️ The dominant unresolved issue: category scarcity

**Request Smuggling is NOT EVALUABLE (D18)** — 7 train rows, **zero eval rows**. No category-level accuracy, recall, or other performance claim may be made for it. Recorded in the manifest under `not_evaluable_categories`, determined from the rendered split rather than asserted by hand.

**11 categories are marked INSUFFICIENT DATA** (<100 unique logical groups): Request Smuggling (7), Insecure Deserialization (12), HPP (20), CRLF (21), XPath (24), CSRF (31), GraphQL (74), LDAP (75), JWT (80), NoSQL (83), XXE (98). Neither cap affects any of them — all sit far below 2,500.

This is a *source material* problem (PayloadsAllTheThings has 56 fenced lines for CSRF, 61 for smuggling), not a generator problem, and per D14 nothing was fabricated to inflate them.

### Size caution

The finalized dataset is 31,340 rows, down from 53,756 uncapped and 99,132 historical. Method-stratified balancing trims hard once BLOCK shrinks (34,248 train + 5,567 eval rows trimmed). Smaller and valid is the intended trade (D7), but this remains a small dataset for a 1.1B model — worth weighing before training.

---

## 13. Current ordered plan

Supersedes the v4 plan in §7. Decisions D1–D18 are recorded in `DECISIONS.md`.

| Step | Experiment | Status |
|------|-----------|--------|
| **E0** | Dataset integrity gate (`check_dataset.py`) | **DONE 2026-08-16** — current dataset reports **FAIL**, as expected |
| **E1** | Port `finetune.py` to TRL 1.4 / transformers 5.8; smoke-test | **DONE 2026-08-17 — PASS** (`reports/e1_training_pipeline_smoke.txt`). Tooling unblocked. |
| — | Documentation correction (this file + `DECISIONS.md` + `README.md`) | CONTEXT + DECISIONS done 2026-08-16; **README still stale** |
| **E2** | Envelope neutralization — shared envelope + shape matching | **DONE 2026-08-17** (`reports/e2_e3_clean_dataset.txt`). Strongest incidental baseline 93.72% → 51.16%. |
| **E3** | Leakage-free grouped split | **DONE 2026-08-17.** Leakage 26.65% → 0.00%; duplicates → 0.00%. |
| — | **Review the candidate clean dataset** | **BLOCKING — next action.** No training until reviewed. |
| **E4** | `###END###` removal (D5) | **DONE 2026-08-17** (`reports/e4_remove_end_token.txt`). Dataset regenerated; E0 metrics byte-identical. |
| **E5** | Per-category rebalancing | NOT STARTED |
| **E6** | Held-out evasion evaluation | NOT STARTED |
| **E8** | Quantization tradeoff (FP16 vs GGUF Q4_K_M) | NOT STARTED |
| **E9** | Inline overhead decomposition (D3 metrics) | NOT STARTED |
| **E7** | Conventional rule-based baseline | **FUTURE / OPTIONAL per D9** — do not implement now |

**Gate rule:** no training run starts while `check_dataset.py` reports FAIL.

**Core scope per D8:** clean dataset → validated classifier → GGUF/quantized deployment → inline HTTP gateway → security validation → sufficient performance evaluation → physical embedded deployment. Deep comparative studies and architecture extensions are **not** core.

---

## 14. How to Re-Orient at the Start of a New Session

1. Read this file first, then `DECISIONS.md`.
2. **Use `python3.12`, not `python3`** (see §2). This is the #1 gotcha post-reinstall.
3. Read `parse_dataset.py`, `finetune.py`, `test_model.py` for current config — and read §12 first, so you know which of their behaviours are already-identified defects rather than things to rediscover.
4. Check training status: `ls ~/Desktop/firewall-IA/model-output-v3/ 2>/dev/null || echo "not trained yet"`. **As of 2026-08-16 this is "not trained yet" and there is no baseline.**
5. Confirm dataset: `wc -l ~/Desktop/firewall-IA/train.jsonl` (expect ~79,305).
6. **Run the integrity gate: `python3.12 check_dataset.py`.** No training starts while it reports FAIL. Compare against `reports/e0_dataset_integrity_current.txt` to see what changed.
7. Confirm no missing categories: run `parse_dataset.py` only if regenerating, and check for `[SKIP]` lines. `[SKIP]` is an ERROR, not a warning.
8. Verify PayloadsAllTheThings is at the recorded commit `e961fef231d8327bae83b563fab50aec2e6b77c0` (§6) if categories look off.

### Language discipline

Never state that the system is "more secure" or "faster" than a conventional mechanism unless an experiment in `reports/` demonstrates it. Distinguish observation / measurement / hypothesis / interpretation / conclusion. Prefer "under the tested conditions…", "the experiment indicates…", "additional testing is required…". Do not present the 91% figure as a current result (§3).