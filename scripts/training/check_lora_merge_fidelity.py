#!/usr/bin/env python3
"""Deployment-path diagnostic: does `merge_and_unload()` preserve a QLoRA adapter's greedy outputs?

First step of TinyLlama + LoRA → merge → GGUF → llama.cpp (D8 item 3, D10, D23). It compares, on the
SAME prompts and greedy decoding:

  A. runtime   : base loaded 4-bit NF4 (bf16 compute) + PEFT adapter — the configuration that is served
                 today for V4 (`control_plane/inference_core.load_model`, imported read-only, not changed)
                 and the configuration the V5 adapter was trained against;
  B. unmerged  : base bf16 + PEFT adapter (isolates the cost of dropping NF4);
  C. merged    : base bf16 with the adapter merged, saved with save_pretrained() and RELOADED from disk —
                 the artifact a GGUF converter would read.

QLoRA trains the adapter against the NF4-DEQUANTIZED base, while merging adds it to the original bf16
weights, so A vs C can differ. B vs C isolates the merge arithmetic itself. This is a FIDELITY diagnostic
between runtimes, not an accuracy measurement. Inputs are the stage-4 synthetic fixture texts only (no
V4 eval set, no INTERNAL TEST, no External Test). Nothing touches the gateway, and no GGUF is produced
(llama.cpp is not installed).

    python3.12 scripts/training/check_lora_merge_fidelity.py --adapter model-output-v4-clean --format v4 \
        --dataset <FIXTURE_DIR> --n 64 --report reports/v5/training-readiness/merge-fidelity/v4_clean.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import v5_train_data as D  # noqa: E402  (puts control_plane/ on sys.path)
import v5_output_contract as OC  # noqa: E402
import v5_tokenization as T  # noqa: E402

BASE = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
REVISION = "fe8a4ea1ffedaf415f4da2f062534de366a451e6"


def prompts(fmt, tok, rows):
    if fmt == "v4":
        import inference_core as IC   # read-only: the V4 prompt exactly as served
        return [tok(IC.build_prompt(r["text"]))["input_ids"] for r in rows]
    return [T.encode_prompt(tok, T.V5_CANDIDATE_TEMPLATE, r["text"]) for r in rows]


def decide(fmt, text):
    if fmt == "v4":
        import inference_core as IC
        d, _, st = IC.parse_prediction(text)
        return d if st == "ok" else "INVALID"
    p = OC.parse_v5_output(text, OC.PILOT_VOCABULARY, ended_with_eos=True)
    return p.decision if p.status == OC.OK else "INVALID"


def generate_all(model, tok, ids_list, torch, max_new):
    out, t0 = [], time.perf_counter()
    with torch.no_grad():
        for ids in ids_list:
            x = torch.tensor([ids], device=model.device)
            g = model.generate(input_ids=x, attention_mask=torch.ones_like(x), do_sample=False,
                               max_new_tokens=max_new, pad_token_id=tok.eos_token_id, eos_token_id=tok.eos_token_id)
            new = g[0, len(ids):].tolist()
            body = new[: new.index(tok.eos_token_id)] if tok.eos_token_id in new else new
            out.append({"ids": body, "text": tok.decode(body, skip_special_tokens=True),
                        "eos": tok.eos_token_id in new})
    return out, round(time.perf_counter() - t0, 2)


def dequantized_nf4_base(base, revision, bnb, torch):
    """bf16 model whose Linear weights are exactly dequantize(NF4(W)) under `bnb` (the runtime config)."""
    import bitsandbytes.functional as BF
    from transformers import AutoModelForCausalLM
    q = AutoModelForCausalLM.from_pretrained(base, revision=revision, quantization_config=bnb, device_map={"": 0},
                                             local_files_only=True)
    deq = {}
    for name, mod in q.named_modules():
        w = getattr(mod, "weight", None)
        if w is not None and getattr(w, "quant_state", None) is not None:
            deq[name] = BF.dequantize_4bit(w.data, w.quant_state).to(torch.bfloat16).cpu()
    del q
    torch.cuda.empty_cache()
    m = AutoModelForCausalLM.from_pretrained(base, revision=revision, torch_dtype=torch.bfloat16, device_map={"": 0},
                                             local_files_only=True)
    with torch.no_grad():
        for name, w in deq.items():
            tgt = m.get_submodule(name).weight
            assert tgt.shape == w.shape, (name, tgt.shape, w.shape)
            tgt.copy_(w.to(tgt.device))
    return m


def compare(a, b, fmt):
    same_ids = sum(x["ids"] == y["ids"] for x, y in zip(a, b))
    same_dec = sum(decide(fmt, x["text"]) == decide(fmt, y["text"]) for x, y in zip(a, b))
    diffs = [{"i": i, "a": x["text"], "b": y["text"]} for i, (x, y) in enumerate(zip(a, b)) if x["ids"] != y["ids"]]
    return {"n": len(a), "identical_generations": same_ids, "identical_decisions": same_dec, "differences": diffs[:10]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--format", required=True, choices=("v4", "v5"))
    ap.add_argument("--dataset", required=True, help="stage-4 SYNTHETIC fixture dir (SMOKE gate is applied)")
    ap.add_argument("--n", type=int, default=64)
    ap.add_argument("--report", required=True)
    ap.add_argument("--merged-dir", default=None, help="default: model-output-v5/merge-check/<adapter name>")
    a = ap.parse_args(argv)

    recipe, rsha = D.load_recipe(os.path.join(HERE, "v5_training_recipe_v1.json"))
    prep = D.prepare(D.SMOKE, a.dataset, os.path.join(D.OUTPUT_ROOT, "smoke", "merge-check"), recipe, rsha)
    rows = (prep.validation_rows + prep.train_rows)[: a.n]

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    import peft
    import transformers

    tok = AutoTokenizer.from_pretrained(BASE, revision=REVISION, local_files_only=True)
    ids_list = prompts(a.format, tok, rows)
    max_new = 40 if a.format == "v4" else 17
    rec = {"schema": "v5-merge-fidelity/v1", "adapter": os.path.relpath(os.path.abspath(a.adapter), D.REPO_ROOT),
           "adapter_sha256": D.sha256_file(os.path.join(a.adapter, "adapter_model.safetensors")),
           "format": a.format, "inputs": f"{len(rows)} synthetic fixture texts (manifest {prep.manifest_sha256[:12]})",
           "note": "fidelity between runtimes on synthetic inputs; NOT an accuracy or quality measurement",
           "versions": {"torch": torch.__version__, "transformers": transformers.__version__, "peft": peft.__version__}}

    # A — runtime (NF4 + adapter, inference_core's quantization config)
    # V4: inference_core's runtime config (no double quant). V5: the recipe's training config (double quant).
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=a.format == "v5")
    rec["runtime_A_double_quant"] = a.format == "v5"
    m = AutoModelForCausalLM.from_pretrained(BASE, revision=REVISION, quantization_config=bnb, device_map={"": 0},
                                             local_files_only=True)
    m = PeftModel.from_pretrained(m, a.adapter).eval()
    gen_a, rec["seconds_A"] = generate_all(m, tok, ids_list, torch, max_new)
    del m
    torch.cuda.empty_cache()

    # B — bf16 base + adapter (unmerged); C — merged, saved and reloaded
    m = AutoModelForCausalLM.from_pretrained(BASE, revision=REVISION, torch_dtype=torch.bfloat16, device_map={"": 0},
                                             local_files_only=True)
    m = PeftModel.from_pretrained(m, a.adapter).eval()
    gen_b, rec["seconds_B"] = generate_all(m, tok, ids_list, torch, max_new)
    merged = m.merge_and_unload()
    mdir = a.merged_dir or os.path.join(D.OUTPUT_ROOT, "merge-check", os.path.basename(os.path.normpath(a.adapter)))
    os.makedirs(mdir, exist_ok=True)
    merged.save_pretrained(mdir, safe_serialization=True)
    tok.save_pretrained(mdir)
    del m, merged
    torch.cuda.empty_cache()
    m = AutoModelForCausalLM.from_pretrained(mdir, torch_dtype=torch.bfloat16, device_map={"": 0}).eval()
    gen_c, rec["seconds_C"] = generate_all(m, tok, ids_list, torch, max_new)
    from safetensors import safe_open
    keys = []
    for f in sorted(os.listdir(mdir)):
        if f.endswith(".safetensors"):
            with safe_open(os.path.join(mdir, f), "pt") as fh:
                keys += list(fh.keys())
    rec["merged"] = {"dir": os.path.relpath(mdir, D.REPO_ROOT),
                     "bytes": sum(os.path.getsize(os.path.join(mdir, f)) for f in os.listdir(mdir)),
                     "tensors": len(keys), "lora_tensors_left": sum("lora_" in k for k in keys),
                     "architectures": json.load(open(os.path.join(mdir, "config.json")))["architectures"]}
    del m
    torch.cuda.empty_cache()

    # D — QLoRA-faithful merge: dequantize the SAME NF4 base the adapter sees (A), merge into it,
    # save, reload. Removes the NF4 → bf16 base shift that separates A from C.
    fdir = mdir + "-nf4dequant"
    m = dequantized_nf4_base(BASE, REVISION, bnb, torch)
    m = PeftModel.from_pretrained(m, a.adapter).eval()
    m.merge_and_unload().save_pretrained(fdir, safe_serialization=True)
    tok.save_pretrained(fdir)
    del m
    torch.cuda.empty_cache()
    m = AutoModelForCausalLM.from_pretrained(fdir, torch_dtype=torch.bfloat16, device_map={"": 0}).eval()
    gen_d, rec["seconds_D"] = generate_all(m, tok, ids_list, torch, max_new)
    rec["faithful_merged_dir"] = os.path.relpath(fdir, D.REPO_ROOT)
    rec["A_vs_D_runtime_vs_faithful_merged_artifact"] = compare(gen_a, gen_d, a.format)
    rec["decisions_D"] = {k: sum(decide(a.format, g["text"]) == k for g in gen_d) for k in ("ALLOW", "BLOCK", "INVALID")}
    rec["A_vs_B_nf4_vs_bf16_unmerged"] = compare(gen_a, gen_b, a.format)
    rec["B_vs_C_merge_arithmetic"] = compare(gen_b, gen_c, a.format)
    rec["A_vs_C_runtime_vs_merged_artifact"] = compare(gen_a, gen_c, a.format)
    rec["decisions_A"] = {k: sum(decide(a.format, g["text"]) == k for g in gen_a) for k in ("ALLOW", "BLOCK", "INVALID")}
    rec["decisions_C"] = {k: sum(decide(a.format, g["text"]) == k for g in gen_c) for k in ("ALLOW", "BLOCK", "INVALID")}
    D.os.makedirs(os.path.dirname(a.report), exist_ok=True)
    with open(a.report, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    for k in ("A_vs_B_nf4_vs_bf16_unmerged", "B_vs_C_merge_arithmetic", "A_vs_C_runtime_vs_merged_artifact",
              "A_vs_D_runtime_vs_faithful_merged_artifact"):
        r = rec[k]
        print(f"{k}: generations {r['identical_generations']}/{r['n']} decisions {r['identical_decisions']}/{r['n']}")
    print("decisions A", rec["decisions_A"], "C", rec["decisions_C"], "D", rec["decisions_D"])
    print("merged", rec["merged"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
