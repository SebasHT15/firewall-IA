# Graph Report - .  (2026-05-29)

## Corpus Check
- Corpus is ~10,543 words - fits in a single context window. You may not need a graph.

## Summary
- 70 nodes · 94 edges · 16 communities (10 shown, 6 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.85)
- Token cost: 3,800 input · 1,950 output

## Community Hubs (Navigation)
- [[_COMMUNITY_FastAPI Classifier Service|FastAPI Classifier Service]]
- [[_COMMUNITY_Deployment & Architecture|Deployment & Architecture]]
- [[_COMMUNITY_Dataset & Attack Categories|Dataset & Attack Categories]]
- [[_COMMUNITY_Fine-tuning Pipeline|Fine-tuning Pipeline]]
- [[_COMMUNITY_Dataset Construction|Dataset Construction]]
- [[_COMMUNITY_CSIC 2010 Integration|CSIC 2010 Integration]]
- [[_COMMUNITY_URL Obfuscation Encoding|URL Obfuscation Encoding]]
- [[_COMMUNITY_Obfuscation Sampling|Obfuscation Sampling]]
- [[_COMMUNITY_SQL Comment Injection|SQL Comment Injection]]
- [[_COMMUNITY_SQL Case Variation|SQL Case Variation]]
- [[_COMMUNITY_Whitespace Obfuscation|Whitespace Obfuscation]]
- [[_COMMUNITY_HTML Entity Encoding|HTML Entity Encoding]]
- [[_COMMUNITY_Bash IFS Obfuscation|Bash IFS Obfuscation]]
- [[_COMMUNITY_Unicode Escape Obfuscation|Unicode Escape Obfuscation]]

## God Nodes (most connected - your core abstractions)
1. `finetune.py` - 7 edges
2. `build_obfuscated_examples()` - 6 edges
3. `build_dataset()` - 5 edges
4. `Dataset v3-rebuild (99K)` - 5 edges
5. `Model v3-rebuild (Adapter)` - 5 edges
6. `firewall-IA README` - 5 edges
7. `obf_url_encode()` - 4 edges
8. `main()` - 4 edges
9. `firewall-IA Project` - 4 edges
10. `parse_dataset.py` - 4 edges

## Surprising Connections (you probably didn't know these)
- `ALLOW/BLOCK Verdict Format` --conceptually_related_to--> `classifier_api.py (FastAPI Service)`  [INFERRED]
  README.md → CONTEXT.md
- `v3 Training Results (91% accuracy)` --references--> `Model v3-rebuild (Adapter)`  [EXTRACTED]
  README.md → CONTEXT.md
- `firewall-IA README` --references--> `19 Attack Categories`  [EXTRACTED]
  README.md → CONTEXT.md
- `firewall-IA README` --references--> `firewall-IA Project`  [EXTRACTED]
  README.md → CONTEXT.md
- `firewall-IA README` --references--> `TinyLlama-1.1B-Chat`  [EXTRACTED]
  README.md → CONTEXT.md

## Hyperedges (group relationships)
- **Training Pipeline: parse_dataset → finetune → test_model** — firewall_ia_context_parse_dataset, firewall_ia_context_finetune, firewall_ia_context_test_model, firewall_ia_context_model_v3_rebuild [EXTRACTED 1.00]
- **Dataset Sources: PayloadsAllTheThings + CSIC 2010 + Hardcoded Payloads + Synthetic ALLOW** — firewall_ia_context_payloads_all_the_things, firewall_ia_context_csic2010, firewall_ia_context_dataset_v3_rebuild, firewall_ia_context_parse_dataset [EXTRACTED 1.00]
- **Inference Deployment: GGUF export → llama.cpp → Inline Proxy** — firewall_ia_context_gguf_export, firewall_ia_readme_llama_cpp, firewall_ia_context_inline_proxy, firewall_ia_context_classifier_api [INFERRED 0.85]

## Communities (16 total, 6 thin omitted)

### Community 0 - "FastAPI Classifier Service"
Cohesion: 0.23
Nodes (10): BaseModel, FastAPI, classify(), _classify_raw(), ClassifyRequest, ClassifyResponse, lifespan(), firewall-IA — classification engine (control plane).  Wraps the v3 QLoRA-fine-tu (+2 more)

### Community 1 - "Deployment & Architecture"
Cohesion: 0.20
Nodes (11): classifier_api.py (FastAPI Service), CSIC Envelope Bias (Konqueror UA / JSESSIONID), GGUF Export for llama.cpp, Inline HTTP Proxy (Data Plane), Model v3-rebuild (Adapter), Proxy as Data Factory (Future Strategy), v4 Improvement Plan, llama.cpp Embedded Inference (+3 more)

### Community 2 - "Dataset & Attack Categories"
Cohesion: 0.36
Nodes (8): 19 Attack Categories, CSIC 2010 HTTP Dataset, csic_database.csv, Dataset v3-rebuild (99K), parse_dataset.py, PayloadsAllTheThings, Python 3.12 ML Environment, test_model.py

### Community 3 - "Fine-tuning Pipeline"
Cohesion: 0.43
Nodes (7): finetune.py, HuggingFace PEFT, LoRA / QLoRA 4-bit Fine-tuning, firewall-IA Project, TinyLlama-1.1B-Chat, TRL SFTTrainer, firewall-IA README

### Community 4 - "Dataset Construction"
Cohesion: 0.40
Nodes (5): build_dataset(), build_hardcoded_categories(), extract_payloads_from_md(), Genera ejemplos BLOCK para categorías no cubiertas por PayloadsAllTheThings:, wrap_in_http()

### Community 5 - "CSIC 2010 Integration"
Cohesion: 0.83
Nodes (3): categorize_csic_anomalous(), integrate_csic2010(), main()

### Community 6 - "URL Obfuscation Encoding"
Cohesion: 0.50
Nodes (4): obf_double_url_encode(), obf_url_encode(), Encode key attack chars with %XX: ' < > space ; =, URL-encode first, then encode each % as %25 (double encoding)

### Community 7 - "Obfuscation Sampling"
Cohesion: 0.67
Nodes (3): build_obfuscated_examples(), Sample target_count (payload, label) pairs from the raw BLOCK pool,     apply a, _transforms_for()

## Knowledge Gaps
- **6 isolated node(s):** `str`, `HuggingFace PEFT`, `TRL SFTTrainer`, `ALLOW/BLOCK Verdict Format`, `v3 Training Results (91% accuracy)` (+1 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `finetune.py` connect `Fine-tuning Pipeline` to `Deployment & Architecture`, `Dataset & Attack Categories`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Why does `Model v3-rebuild (Adapter)` connect `Deployment & Architecture` to `Dataset & Attack Categories`, `Fine-tuning Pipeline`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Why does `Dataset v3-rebuild (99K)` connect `Dataset & Attack Categories` to `Fine-tuning Pipeline`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **What connects `str`, `firewall-IA — classification engine (control plane).  Wraps the v3 QLoRA-fine-tu`, `Replicates test_model.py classify() 1:1, returning structured parts.` to the rest of the system?**
  _18 weakly-connected nodes found - possible documentation gaps or missing edges._