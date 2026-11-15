#!/usr/bin/env python3
"""Deployment-path diagnostic: GGUF + llama.cpp vs the HF NF4 runtime, on the SAME token ids.

Second step of TinyLlama + LoRA → merge → GGUF → llama.cpp (D8 item 3, D10, D23; see
`check_lora_merge_fidelity.py` for the merge step). For each GGUF file it:

  1. starts `llama-server` on 127.0.0.1 (one slot, fixed threads), never touching the gateway;
  2. TOKEN PARITY — tokenizes every prompt TEXT with llama.cpp (`/tokenize`, special-token parsing on,
     as the V4 prompt relies on) and compares id-for-id with the HF tokenizer;
  3. FIDELITY — sends the HF prompt IDS (`/completion` with a token array, greedy: temperature 0,
     top_k 1) and compares the generated ids and the decisions with the HF reference (base 4-bit NF4
     + PEFT adapter, the configuration `control_plane/inference_core.load_model` serves — imported
     read-only, not changed);
  4. records llama.cpp's own model-side timings (prompt + generation) as a DIAGNOSTIC of this machine's
     CPU build only — not a D31/D32 benchmark, not a D36 result.

Inputs are the stage-4 synthetic fixture texts (SMOKE gate): fidelity between runtimes, NOT accuracy.
No V4 eval set, no INTERNAL TEST, no External Test.

    python3.12 scripts/training/check_gguf_fidelity.py --format v4 --adapter model-output-v4-clean \
        --dataset <FIXTURE_DIR> --gguf model-output-v5/gguf/v4-clean/*.gguf \
        --server ~/opt/llama.cpp/build/bin/llama-server --report <json>
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_lora_merge_fidelity as MF  # noqa: E402  (prompts / decide / generate_all, BASE / REVISION)
import v5_train_data as D  # noqa: E402


def _post(url, payload, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _wait_ready(base, proc, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"llama-server exited with {proc.returncode}")
        try:
            with urllib.request.urlopen(base + "/health", timeout=2) as r:
                if json.loads(r.read()).get("status") == "ok":
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("llama-server not ready")


def decide_eos(fmt, text, ended_with_eos):
    """V4: the served regex parser (EOS not required). V5: the strict parser, which needs EOS."""
    if fmt == "v4":
        return MF.decide(fmt, text)
    p = MF.OC.parse_v5_output(text, MF.OC.PILOT_VOCABULARY, ended_with_eos=ended_with_eos)
    return p.decision if p.status == MF.OC.OK else "INVALID"


def llama_cpp_build(server):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(server))))
    head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    tag = subprocess.run(["git", "-C", root, "describe", "--tags", "--exact-match"], capture_output=True, text=True).stdout.strip()
    ver = subprocess.run([server, "--version"], capture_output=True, text=True)
    return {"commit": head, "tag": tag or None, "version": (ver.stdout + ver.stderr).strip().splitlines()[-2:]}


def run_gguf(server, gguf, port, threads, ids_list, texts, max_new, eos_id, log_path):
    base = f"http://127.0.0.1:{port}"
    cmd = [server, "-m", gguf, "--host", "127.0.0.1", "--port", str(port), "-c", "2048", "-np", "1",
           "-t", str(threads), "--no-warmup"]
    with open(log_path, "w") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        try:
            _wait_ready(base, proc)
            tok_parity, gens = [], []
            for text, ids in zip(texts, ids_list):
                if text is None:                 # V5: ids only, never tokenized from text
                    continue
                got = _post(base + "/tokenize", {"content": text, "add_special": True, "parse_special": True})["tokens"]
                tok_parity.append(got == ids)
            _post(base + "/completion", {"prompt": ids_list[0], "n_predict": 1, "temperature": 0})   # warm-up
            for ids in ids_list:
                r = _post(base + "/completion", {
                    "prompt": ids, "n_predict": max_new, "temperature": 0, "top_k": 1, "seed": 0,
                    "cache_prompt": False, "return_tokens": True, "stream": False})
                toks = list(r.get("tokens") or [])
                ended = r.get("stop_type") == "eos" or (eos_id in toks)
                body = toks[: toks.index(eos_id)] if eos_id in toks else toks
                t = r.get("timings", {})
                gens.append({"ids": body, "text": r.get("content", ""), "eos": ended,
                             "prompt_ms": t.get("prompt_ms"), "predicted_ms": t.get("predicted_ms"),
                             "prompt_n": t.get("prompt_n"), "predicted_n": t.get("predicted_n")})
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
    return tok_parity, gens


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--format", required=True, choices=("v4", "v5"))
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--dataset", required=True, help="stage-4 SYNTHETIC fixture dir (SMOKE gate is applied)")
    ap.add_argument("--gguf", nargs="+", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--port", type=int, default=18093)
    ap.add_argument("--n", type=int, default=64)
    ap.add_argument("--report", required=True)
    a = ap.parse_args(argv)

    recipe, rsha = D.load_recipe(os.path.join(HERE, "v5_training_recipe_v1.json"))
    prep = D.prepare(D.SMOKE, a.dataset, os.path.join(D.OUTPUT_ROOT, "smoke", "gguf-check"), recipe, rsha)
    rows = (prep.validation_rows + prep.train_rows)[: a.n]

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tok = AutoTokenizer.from_pretrained(MF.BASE, revision=MF.REVISION, local_files_only=True)
    ids_list = MF.prompts(a.format, tok, rows)
    if a.format == "v4":
        import inference_core as IC
        texts = [IC.build_prompt(r["text"]) for r in rows]
    else:
        texts = [None] * len(rows)          # V5 is never tokenized from text (spec §5.4): ids only
    max_new = 40 if a.format == "v4" else 17

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=a.format == "v5")
    m = AutoModelForCausalLM.from_pretrained(MF.BASE, revision=MF.REVISION, quantization_config=bnb,
                                             device_map={"": 0}, local_files_only=True)
    m = PeftModel.from_pretrained(m, a.adapter).eval()
    ref, ref_s = MF.generate_all(m, tok, ids_list, torch, max_new)
    del m
    torch.cuda.empty_cache()

    rec = {"schema": "v5-gguf-fidelity/v1", "format": a.format,
           "adapter": os.path.relpath(os.path.abspath(a.adapter), D.REPO_ROOT),
           "inputs": f"{len(rows)} synthetic fixture texts (manifest {prep.manifest_sha256[:12]})",
           "note": "fidelity between runtimes on synthetic inputs; NOT accuracy. Timings: CPU build diagnostic only, "
                   "not a D31/D32 benchmark and not a D36 result",
           "reference": {"runtime": "HF 4-bit NF4 + PEFT adapter (GPU)", "seconds_total": ref_s,
                         "decisions": {k: sum(MF.decide(a.format, g["text"]) == k for g in ref)
                                       for k in ("ALLOW", "BLOCK", "INVALID")}},
           "server": {"binary": a.server, "threads": a.threads, "build": llama_cpp_build(a.server),
                      "args": ["-c", "2048", "-np", "1", "-t", str(a.threads), "--no-warmup", "--host", "127.0.0.1"],
                      "request": {"prompt": "HF token ids (V4: tokenizer(build_prompt); V5: encode_prompt)",
                                  "n_predict": max_new, "temperature": 0, "top_k": 1, "seed": 0,
                                  "cache_prompt": False}},
           "reference_outputs": [{"i": j, "text_sha256": r["meta"]["text_sha256"], "output": x["text"], "eos": x["eos"]}
                                 for j, (r, x) in enumerate(zip(rows, ref))],
           "results": {}}
    report_dir = os.path.dirname(os.path.abspath(a.report))
    os.makedirs(report_dir, exist_ok=True)
    for i, g in enumerate(a.gguf):
        name = os.path.basename(g)
        print(f"[{name}] serving on 127.0.0.1:{a.port + i} ...", flush=True)
        parity, gens = run_gguf(a.server, g, a.port + i, a.threads, ids_list, texts, max_new, tok.eos_token_id,
                                os.path.join(report_dir, f"llama-server.{name}.log"))
        same_ids = sum(x["ids"] == y["ids"] for x, y in zip(ref, gens))
        cases, flips = [], []
        for j, (r, x, y) in enumerate(zip(rows, ref, gens)):
            g_text = tok.decode(y["ids"], skip_special_tokens=True)
            hd, gd = decide_eos(a.format, x["text"], x["eos"]), decide_eos(a.format, g_text, y["eos"])
            case = {"i": j, "text_sha256": r["meta"]["text_sha256"], "prompt_tokens": len(ids_list[j]),
                    "hf_output": x["text"], "gguf_output": g_text, "hf_decision": hd, "gguf_decision": gd,
                    "gguf_ended_on_eos": y["eos"], "identical_ids": x["ids"] == y["ids"]}
            cases.append(case)
            if hd != gd:
                flips.append(dict(case, direction=f"{hd}->{gd}", input_text=r["text"]))   # synthetic fixture text
        same_dec = len(cases) - len(flips)
        tot = [y["prompt_ms"] + y["predicted_ms"] for y in gens if y["prompt_ms"] is not None]
        res = {"file_bytes": os.path.getsize(g), "sha256": D.sha256_file(g),
               "token_parity_text": None if a.format == "v5" else f"{sum(parity)}/{len(parity)}",
               "identical_generations": f"{same_ids}/{len(ref)}", "identical_decisions": f"{same_dec}/{len(ref)}",
               "ended_on_eos": sum(y["eos"] for y in gens),
               "decisions": {k: sum(c["gguf_decision"] == k for c in cases) for k in ("ALLOW", "BLOCK", "INVALID")},
               "flip_directions": {d: sum(f["direction"] == d for f in flips) for d in sorted({f["direction"] for f in flips})},
               "model_ms_cpu": {"median": round(statistics.median(tot), 1),
                                "p95": round(sorted(tot)[int(0.95 * (len(tot) - 1))], 1),
                                "max": round(max(tot), 1), "n": len(tot)},
               "decision_flips": flips, "cases": cases}
        rec["results"][name] = res
        print(f"  token parity {res['token_parity_text']}  generations {res['identical_generations']}  "
              f"decisions {res['identical_decisions']} flips {res['flip_directions']}  EOS {res['ended_on_eos']}  CPU ms {res['model_ms_cpu']}",
              flush=True)
    with open(a.report, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
