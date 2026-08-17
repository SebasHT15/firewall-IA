---
type: "query"
date: "2026-05-29T23:17:46.542683+00:00"
question: "why does finetune.py bridge dataset pipeline and deployment?"
contributor: "graphify"
source_nodes: ["finetune.py", "Dataset v3-rebuild (99K)", "Model v3-rebuild (Adapter)", "GGUF Export for llama.cpp", "classifier_api.py (FastAPI Service)", "parse_dataset.py"]
---

# Q: why does finetune.py bridge dataset pipeline and deployment?

## Answer

Expanded from original query via vocab: [finetune dataset model training adapter export gguf inference parse api proxy rebuild]. finetune.py has betweenness centrality 0.043 — highest in graph — because it is the only node with edges into all three major communities: Dataset & Attack Categories (via Dataset v3-rebuild references), Fine-tuning Pipeline (its own community with TinyLlama/LoRA/PEFT/SFTTrainer), and Deployment & Architecture (via Model v3-rebuild Adapter → GGUF Export → classifier_api.py). The structural chain is: parse_dataset.py --implements--> Dataset v3-rebuild (99K) --references--> finetune.py --produces--> Model v3-rebuild (Adapter) --conceptually_related_to--> GGUF Export --conceptually_related_to--> llama.cpp Embedded Inference / classifier_api.py. All 7 obfuscation sub-communities feed into the dataset but never reference deployment nodes. classifier_api.py only appears in deployment. finetune.py is the single mandatory pass-through.

## Source Nodes

- finetune.py
- Dataset v3-rebuild (99K)
- Model v3-rebuild (Adapter)
- GGUF Export for llama.cpp
- classifier_api.py (FastAPI Service)
- parse_dataset.py