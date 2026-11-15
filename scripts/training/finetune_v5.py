#!/usr/bin/env python3
"""firewall-IA — V5 QLoRA fine-tuning of TinyLlama-1.1B-Chat, behind SMOKE / EXPERIMENTAL / FINAL gates.

Separate from `finetune.py` (V4-clean, unchanged). The V4 prompt, the V4 text field and TRL's own
tokenization are NOT used: V5 examples are tokenized with the frozen template-safe method of spec §5.4
(`control_plane/v5_tokenization.encode_prompt`) and passed to TRL already tokenized, with a
completion mask. All gates live in `v5_train_data.py`; read its docstring for what each mode requires.

Run with the ML stack (python3.12 on this machine):

    # engineering smoke test on a stage-4 synthetic fixture build (NO quality evidence)
    python3.12 scripts/dataset/v5_fixture.py generate --out <FIXTURE_DIR>
    python3.12 scripts/training/finetune_v5.py --mode smoke --dataset <FIXTURE_DIR> \
        --report-dir reports/v5/training-readiness/smoke-run-001

    # gate check only (no model is loaded) — e.g. what FINAL is missing today
    python3.12 scripts/training/finetune_v5.py --mode final --dataset <DIR> --gate-only

Outputs go ONLY to model-output-v5/<mode>/<run_id>/ (gitignored): `adapter/`, `checkpoints/`,
`run_record.json`. `--report-dir` gets a copy of the run record (and is where the console log is teed).

Exit codes: 0 ok · 2 smoke checks failed · 3 gate refused (nothing trained).
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata as md
import json
import math
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import v5_train_data as D  # noqa: E402  (also puts control_plane/ on sys.path)
import v5_output_contract as OC  # noqa: E402
import v5_tokenization as T  # noqa: E402

DEFAULT_RECIPE = os.path.join(HERE, "v5_training_recipe_v1.json")
LIBS = ("torch", "transformers", "trl", "peft", "bitsandbytes", "datasets", "accelerate")
CODE_FILES = (os.path.join(HERE, "finetune_v5.py"), os.path.join(HERE, "v5_train_data.py"),
              os.path.join(D.REPO_ROOT, "scripts", "dataset", "v5_audit_evidence.py"),
              os.path.join(D.REPO_ROOT, "scripts", "dataset", "v5_row_contract.py"),
              os.path.join(D.REPO_ROOT, "scripts", "dataset", "v5_pools_common.py"),
              os.path.join(D.REPO_ROOT, "control_plane", "v5_tokenization.py"),
              os.path.join(D.REPO_ROOT, "control_plane", "v5_output_contract.py"))


def installed_versions() -> dict:
    out = {"python": platform.python_version()}
    for lib in LIBS:
        try:
            out[lib] = md.version(lib)
        except md.PackageNotFoundError:
            out[lib] = None
    return out


def banner(mode: str, out_dir: str):
    print("=" * 78)
    print(f"V5 TRAINER — MODE {mode}")
    print(f"  evidence class: {D.EVIDENCE_CLASS[mode]}")
    if mode == D.SMOKE:
        print("  This run checks that the pipeline works. It is NOT a V5 training run, and its loss")
        print("  and outputs say NOTHING about V5 model quality.")
    elif mode == D.EXPERIMENTAL:
        print("  Provisional, authorized data. Artifacts are provisional: no definitive claim.")
    print(f"  output dir: {out_dir}")
    print("=" * 78, flush=True)


def write_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="V5 QLoRA trainer (gated SMOKE / EXPERIMENTAL / FINAL)")
    ap.add_argument("--mode", required=True, choices=[m.lower() for m in D.MODES])
    ap.add_argument("--dataset", required=True, help="stage-4 generator output dir (manifest.json + rows.*.jsonl)")
    ap.add_argument("--recipe", default=DEFAULT_RECIPE)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--report-dir", default=None, help="copy of run_record.json / refusal record (not /tmp)")
    ap.add_argument("--authorization", default=None, help="EXPERIMENTAL: v5-experimental-authorization/v1 JSON")
    ap.add_argument("--dataset-prereg", default=None, help="FINAL: committed dataset preregistration file")
    ap.add_argument("--freeze-record", default=None, help="FINAL: committed v5-dataset-freeze-record/v1 JSON")
    ap.add_argument("--training-prereg", default=None, help="FINAL: committed v5-training-preregistration/v1 JSON")
    ap.add_argument("--ai-audit-authorization", default=None,
                    help="FINAL, ai_audited datasets only (PROPOSED): committed owner authorization record, separate from "
                         "the other FINAL records; refused while no schema is ratified")
    ap.add_argument("--gate-only", action="store_true", help="run the gates and the tokenization checks, load no model")
    ap.add_argument("--max-steps", type=int, default=None, help="SMOKE only; capped by recipe smoke.max_steps_hard_cap")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    mode = args.mode.upper()
    t0 = time.perf_counter()
    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    recipe, recipe_sha = D.load_recipe(args.recipe)
    manifest_sha_short = "nomanifest"
    mpath = os.path.join(args.dataset, "manifest.json")
    try:
        D.C.assert_not_protected(args.dataset)
        D.C.assert_not_protected(mpath)
    except SystemExit as e:
        print(str(e),file=sys.stderr)
        return 3
    if os.path.isfile(mpath):
        manifest_sha_short = D.sha256_file(mpath)[:12]
    run_id = args.run_id or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{manifest_sha_short}"
    out_dir = os.path.join(D.OUTPUT_ROOT, mode.lower(), run_id)
    banner(mode, out_dir)
    if os.path.exists(out_dir):
        print(f"REFUSED: {out_dir} already exists; runs are never overwritten", file=sys.stderr)
        return 3
    if mode != D.SMOKE and args.max_steps is not None:
        print("REFUSED: --max-steps is a SMOKE-only override", file=sys.stderr)
        return 3

    versions, git = installed_versions(), D.git_state()
    record = {
        "schema": "v5-training-run-record/v1", "mode": mode, "evidence_class": D.EVIDENCE_CLASS[mode],
        "run_id": run_id, "started_utc": started, "output_dir": os.path.relpath(out_dir, D.REPO_ROOT),
        "dataset_dir": os.path.abspath(args.dataset), "recipe_path": os.path.relpath(os.path.abspath(args.recipe), D.REPO_ROOT),
        "recipe_sha256": recipe_sha, "recipe_status": recipe["status"],
        "recipe_unratified_sections": D.unratified_recipe_sections(recipe),
        "template_fingerprint": D.template_fingerprint(recipe), "library_versions": versions, "git": git,
        "code_sha256": {os.path.relpath(p, D.REPO_ROOT): D.sha256_file(p) for p in CODE_FILES},
        "host": {"platform": platform.platform(), "python_executable": sys.executable},
    }

    # ── 1. Gates (dataset, mode, protected material, leakage) ─────────────────────────────
    print("[1/7] Gates ...", flush=True)
    try:
        prep = D.prepare(mode, args.dataset, out_dir, recipe, recipe_sha, authorization=args.authorization,
                         dataset_prereg=args.dataset_prereg, freeze_record=args.freeze_record,
                         training_prereg=args.training_prereg, installed_versions=versions, git=git,
                         ai_audit_authorization=args.ai_audit_authorization,
                         code_paths=CODE_FILES + (os.path.abspath(args.recipe),))
    except D.GateRefused as e:
        print(str(e), file=sys.stderr, flush=True)
        record.update(outcome="REFUSED", refusal=[d.as_dict() for d in e.diagnostics])
        if args.report_dir:
            write_json(os.path.join(args.report_dir, "refusal_record.json"), record)
        return 3
    record["gates"] = {"passed": True, **prep.gate_evidence}
    print(f"      gates PASSED for {mode}: TRAIN={len(prep.train_rows)} VALIDATION={len(prep.validation_rows)}; "
          "INTERNAL_TEST not opened", flush=True)

    # ── 2. Tokenizer, token contract, template-safe examples ──────────────────────────────
    print("[2/7] Tokenizer and template-safe examples ...", flush=True)
    from transformers import AutoTokenizer
    bm = recipe["base_model"]
    tok = AutoTokenizer.from_pretrained(bm["name"], revision=bm["revision"], local_files_only=bm["local_files_only"])
    contract, cdiags = D.measure_contract(tok, recipe)
    train_ex, d1 = D.build_examples(tok, recipe, contract, prep.train_rows)
    val_ex, d2 = D.build_examples(tok, recipe, contract, prep.validation_rows)
    bad = cdiags + d1 + d2
    record["token_contract"] = contract.__dict__
    if bad:
        err = D.GateRefused(mode, D._capped(bad))
        print(str(err), file=sys.stderr, flush=True)
        record.update(outcome="REFUSED", refusal=[d.as_dict() for d in err.diagnostics])
        if args.report_dir:
            write_json(os.path.join(args.report_dir, "refusal_record.json"), record)
        return 3
    lens = sorted(len(e["input_ids"]) for e in train_ex + val_ex)
    record["examples"] = {
        "train": len(train_ex), "validation": len(val_ex), "rejected": 0, "truncated": 0,
        "loss_on": recipe["loss"]["on"], "seq_len_max": lens[-1], "seq_len_median": lens[len(lens) // 2],
        "content_tokens_max": max(e["content_tokens"] for e in train_ex + val_ex),
        "completion_tokens": sorted({e["completion_tokens"] for e in train_ex + val_ex}),
        "outputs_train": _count(e["output"] for e in train_ex),
    }
    print(f"      overhead={contract.overhead} label_budget={contract.label_budget} B={contract.B} "
          f"(template max {contract.template_max_B}); examples train={len(train_ex)} val={len(val_ex)}; "
          f"max seq {lens[-1]} ≤ {contract.max_length}; 0 rejected, 0 truncated", flush=True)
    if mode != D.SMOKE:
        # Fix and RECORD the effective schedule (from the eligible TRAIN count) before any training, so even a
        # small dataset evaluates + checkpoints. Available in gate_record.json too (gate-only).
        record["schedule"] = compute_schedule(recipe, len(train_ex))
        print(f"      schedule: {record['schedule']['total_optimizer_steps']} steps "
              f"({record['schedule']['steps_per_epoch']}/epoch × {record['schedule']['num_train_epochs']}), "
              f"eval+save every {record['schedule']['effective_eval_steps']} "
              f"(~{record['schedule']['expected_evaluations']} evals)", flush=True)
    if args.gate_only:
        record["outcome"] = "GATES_AND_TOKENIZATION_PASSED_NO_TRAINING"
        if args.report_dir:
            write_json(os.path.join(args.report_dir, "gate_record.json"), record)
        print("--gate-only: stopping before any model is loaded.")
        return 0

    return train_and_verify(args, mode, recipe, prep, tok, contract, train_ex, val_ex, out_dir, record, t0)


def _count(it) -> dict:
    out = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return dict(sorted(out.items()))


DESIRED_EVALS = 4   # aim for ~4 evaluations+checkpoints across an epoch-based run


def compute_schedule(recipe, train_rows, num_devices=1) -> dict:
    """Effective training SCHEDULE derived DETERMINISTICALLY from the ratified recipe optimization block and
    the frozen TRAIN size — epochs/batch/accumulation stay the recipe's; only the eval/save/logging CADENCE is
    derived so that even a small dataset actually evaluates and checkpoints. `eval_steps == save_steps` (HF
    requires it for `load_best_model_at_end`). This is RECORDED (run_record/gate_record), never a silent edit
    of the recipe. `train_rows` is the count of ELIGIBLE TRAIN examples (what the gates admitted)."""
    opt = recipe["optimization"]
    per_dev = int(opt["per_device_train_batch_size"])
    accum = int(opt["gradient_accumulation_steps"])
    epochs = int(opt["num_train_epochs"])
    effective_batch = per_dev * accum * max(1, int(num_devices))
    steps_per_epoch = max(1, math.ceil(max(0, int(train_rows)) / effective_batch))
    total_steps = steps_per_epoch * epochs
    recipe_eval = int(opt.get("eval_steps", 0) or 0)
    recipe_log = int(opt.get("logging_steps", 0) or 0)
    eff = max(1, total_steps // DESIRED_EVALS)
    if recipe_eval:
        eff = min(eff, recipe_eval)
    eff = max(1, min(eff, total_steps))                    # at least one eval+save, never past the run end
    eff_log = max(1, min(recipe_log or eff, eff))
    return {"train_rows_eligible": int(train_rows), "num_devices": int(num_devices),
            "per_device_train_batch_size": per_dev, "gradient_accumulation_steps": accum,
            "effective_batch": effective_batch, "num_train_epochs": epochs,
            "steps_per_epoch": steps_per_epoch, "total_optimizer_steps": total_steps,
            "recipe_eval_steps": recipe_eval, "effective_eval_steps": eff, "effective_save_steps": eff,
            "effective_logging_steps": eff_log, "expected_evaluations": total_steps // eff,
            "derivation": (f"effective_eval=save = max(1, min(recipe_eval_steps, total_steps // {DESIRED_EVALS})); "
                           "epochs/batch/accum from the ratified recipe; eval==save for load_best_model_at_end; "
                           "recorded before training, not a silent recipe change")}


def train_and_verify(args, mode, recipe, prep, tok, contract, train_ex, val_ex, out_dir, record, t0) -> int:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, PeftModel, TaskType
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig, TrainerCallback, set_seed
    from trl import SFTConfig, SFTTrainer

    # ── 3. GPU and model ───────────────────────────────────────────────────────────────────
    print("[3/7] GPU and 4-bit base model ...", flush=True)
    if not torch.cuda.is_available():
        print("REFUSED: CUDA is not available", file=sys.stderr)
        return 3
    props = torch.cuda.get_device_properties(0)
    free_b, total_b = torch.cuda.mem_get_info()
    record["gpu"] = {"name": props.name, "capability": f"{props.major}.{props.minor}",
                     "total_vram_gib": round(total_b / 2**30, 2), "free_vram_gib_at_start": round(free_b / 2**30, 2),
                     "bf16_supported": torch.cuda.is_bf16_supported(), "cuda_runtime": torch.version.cuda}
    print(f"      {props.name} · {total_b / 2**30:.1f} GiB total · {free_b / 2**30:.1f} GiB free", flush=True)
    seed = recipe["seed"]["seed"]
    set_seed(seed)
    q = recipe["quantization"]
    bnb = BitsAndBytesConfig(load_in_4bit=q["load_in_4bit"], bnb_4bit_quant_type=q["bnb_4bit_quant_type"],
                             bnb_4bit_use_double_quant=q["bnb_4bit_use_double_quant"],
                             bnb_4bit_compute_dtype=getattr(torch, q["bnb_4bit_compute_dtype"]))
    bm = recipe["base_model"]
    torch.cuda.reset_peak_memory_stats()
    t_load = time.perf_counter()
    model = AutoModelForCausalLM.from_pretrained(bm["name"], revision=bm["revision"], quantization_config=bnb,
                                                 device_map={"": 0}, local_files_only=bm["local_files_only"])
    model.config.use_cache = False
    tok.pad_token = tok.eos_token
    tok.padding_side = "right"
    record["model_load_s"] = round(time.perf_counter() - t_load, 2)
    record["model_loaded_4bit"] = bool(getattr(model, "is_loaded_in_4bit", False))
    print(f"      loaded 4-bit={record['model_loaded_4bit']} in {record['model_load_s']}s; "
          f"VRAM allocated {torch.cuda.memory_allocated() / 2**30:.2f} GiB", flush=True)

    # ── 4. Training ────────────────────────────────────────────────────────────────────────
    print("[4/7] QLoRA training ...", flush=True)
    lo = recipe["lora"]
    lora = LoraConfig(r=lo["r"], lora_alpha=lo["lora_alpha"], lora_dropout=lo["lora_dropout"], bias=lo["bias"],
                      target_modules=lo["target_modules"], task_type=TaskType.CAUSAL_LM, revision=bm["revision"])
    opt = dict(recipe["optimization"])
    opt.pop("status", None)
    opt.pop("source", None)
    if mode == D.SMOKE:
        sm = recipe["smoke"]
        steps = args.max_steps if args.max_steps is not None else sm["max_steps"]
        if steps > sm["max_steps_hard_cap"]:
            print(f"REFUSED: smoke max_steps {steps} > hard cap {sm['max_steps_hard_cap']}", file=sys.stderr)
            return 3
        opt.update(max_steps=steps, per_device_train_batch_size=sm["per_device_train_batch_size"],
                   gradient_accumulation_steps=sm["gradient_accumulation_steps"], learning_rate=sm["learning_rate"],
                   warmup_ratio=sm["warmup_ratio"], eval_steps=sm["eval_steps"], save_steps=sm["save_steps"],
                   logging_steps=sm["logging_steps"], save_total_limit=sm["save_total_limit"])
    else:
        # Apply the effective schedule recorded before training (eval==save so it actually checkpoints even on
        # a small dataset); epochs/batch/accum/lr stay the ratified recipe's.
        sch = record.get("schedule") or compute_schedule(recipe, len(train_ex))
        record["schedule"] = sch
        opt.update(eval_steps=sch["effective_eval_steps"], save_steps=sch["effective_save_steps"],
                   logging_steps=sch["effective_logging_steps"])
    ckpt_dir = os.path.join(out_dir, "checkpoints")
    cfg = SFTConfig(output_dir=ckpt_dir, eval_strategy="steps", save_strategy="steps", report_to="none",
                    seed=seed, data_seed=recipe["seed"]["data_seed"], max_length=contract.max_length,
                    completion_only_loss=recipe["loss"]["on"] == "completion", packing=False, **opt)
    record["training_args"] = {k: v for k, v in sorted(opt.items())} | {
        "max_length": contract.max_length, "completion_only_loss": cfg.completion_only_loss, "packing": False,
        "seed": seed, "data_seed": recipe["seed"]["data_seed"]}

    cols = ("input_ids", "completion_mask")
    train_ds = Dataset.from_list([{c: e[c] for c in cols} for e in train_ex])
    val_ds = Dataset.from_list([{c: e[c] for c in cols} for e in val_ex])

    class LossLog(TrainerCallback):
        def __init__(self):
            self.rows = []

        def on_log(self, _a, state, _c, logs=None, **_k):
            if logs:
                self.rows.append({"step": state.global_step, **{k: v for k, v in logs.items()
                                                                  if isinstance(v, (int, float))}})
                if "loss" in logs:
                    print(f"      step {state.global_step:>4}  loss {logs['loss']:.4f}  "
                          f"grad_norm {logs.get('grad_norm', float('nan')):.3f}", flush=True)

    log_cb = LossLog()
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=train_ds, eval_dataset=val_ds, peft_config=lora,
                         processing_class=tok, callbacks=[log_cb])
    trainable = [(n, p) for n, p in trainer.model.named_parameters() if p.requires_grad]
    record["trainable"] = {"params": sum(p.numel() for _, p in trainable),
                           "total_params": sum(p.numel() for p in trainer.model.parameters()),
                           "lora_tensors": sum(1 for n, _ in trainable if "lora" in n.lower()),
                           "non_lora_trainable": [n for n, _ in trainable if "lora" not in n.lower()],
                           "dtypes": sorted({str(p.dtype) for _, p in trainable})}
    _check_training_batch(trainer, record)
    t_train = time.perf_counter()
    train_out = trainer.train()
    record["train_s"] = round(time.perf_counter() - t_train, 2)
    eval_metrics = trainer.evaluate()
    record["train_metrics"] = {k: v for k, v in train_out.metrics.items()}
    record["eval_metrics_validation"] = eval_metrics
    record["loss_log"] = log_cb.rows
    record["loss_stability"] = loss_stability([r["loss"] for r in log_cb.rows if "loss" in r])
    record["vram_peak_training"] = {"allocated_gib": round(torch.cuda.max_memory_allocated() / 2**30, 3),
                                    "reserved_gib": round(torch.cuda.max_memory_reserved() / 2**30, 3)}
    print(f"      trained in {record['train_s']}s; eval_loss(VALIDATION)={eval_metrics.get('eval_loss'):.4f}; "
          f"peak VRAM allocated {record['vram_peak_training']['allocated_gib']} GiB "
          f"reserved {record['vram_peak_training']['reserved_gib']} GiB", flush=True)

    # ── 5. Save adapter ────────────────────────────────────────────────────────────────────
    print("[5/7] Saving LoRA adapter ...", flush=True)
    adapter_dir = os.path.join(out_dir, "adapter")
    trainer.model.save_pretrained(adapter_dir)
    tok.save_pretrained(adapter_dir)
    record["adapter"] = adapter_inventory(adapter_dir)
    record["checkpoints"] = sorted(d for d in os.listdir(ckpt_dir) if d.startswith("checkpoint-"))
    print(f"      adapter {record['adapter']['adapter_model_bytes'] / 2**20:.1f} MiB, "
          f"{record['adapter']['tensor_count']} tensors, non-LoRA tensors: {record['adapter']['non_lora_tensors']}; "
          f"checkpoints {record['checkpoints']}", flush=True)

    # ── 6. Reload and compare ──────────────────────────────────────────────────────────────
    print("[6/7] Reloading base + adapter from disk ...", flush=True)
    trained = trainer.model
    trained.eval()
    probe = val_ex[: min(4, len(val_ex))]
    ref_logits = completion_logits(trained, probe, torch)
    base2 = AutoModelForCausalLM.from_pretrained(bm["name"], revision=bm["revision"], quantization_config=bnb,
                                                 device_map={"": 0}, local_files_only=bm["local_files_only"])
    reloaded = PeftModel.from_pretrained(base2, adapter_dir)
    reloaded.eval()
    new_logits = completion_logits(reloaded, probe, torch)
    diffs = [float((a - b).abs().max()) for a, b in zip(ref_logits, new_logits)]
    agree = [bool((a.argmax(-1) == b.argmax(-1)).all()) for a, b in zip(ref_logits, new_logits)]
    last_ckpt = os.path.join(ckpt_dir, record["checkpoints"][-1]) if record["checkpoints"] else None
    ckpt_ok = None
    if last_ckpt:
        base3 = AutoModelForCausalLM.from_pretrained(bm["name"], revision=bm["revision"], quantization_config=bnb,
                                                     device_map={"": 0}, local_files_only=bm["local_files_only"])
        ckpt_model = PeftModel.from_pretrained(base3, last_ckpt)
        ckpt_ok = all(math.isfinite(float(x.float().abs().max())) for x in completion_logits(ckpt_model, probe[:1], torch))
        del ckpt_model, base3
    record["reload"] = {"probe_examples": len(probe), "max_abs_logit_diff": diffs,
                        "argmax_identical_on_completion": agree, "checkpoint_reloaded": last_ckpt and
                        os.path.relpath(last_ckpt, D.REPO_ROOT), "checkpoint_forward_finite": ckpt_ok}
    print(f"      reload: max |Δlogit| per probe {['%.4f' % x for x in diffs]}; argmax identical {agree}; "
          f"checkpoint {record['checkpoints'][-1] if last_ckpt else None} forward finite: {ckpt_ok}", flush=True)

    # ── 7. Inference and strict output format (reloaded adapter) ───────────────────────────
    print("[7/7] Greedy inference with the reloaded adapter + strict V5 parser ...", flush=True)
    n = recipe["smoke"]["generation_checks"] if mode == D.SMOKE else len(prep.validation_rows)
    record["inference"] = run_generation(reloaded, tok, recipe, contract, prep.validation_rows[:n], torch)
    inf = record["inference"]
    print(f"      {inf['n']} VALIDATION prompts: status {inf['status_counts']}, ended on EOS {inf['ended_with_eos']}, "
          f"matches expected {inf['matches_expected']} (fixture format check, not a quality metric)", flush=True)

    record["duration_total_s"] = round(time.perf_counter() - t0, 2)
    record["vram_peak_overall"] = {"allocated_gib": round(torch.cuda.max_memory_allocated() / 2**30, 3),
                                   "reserved_gib": round(torch.cuda.max_memory_reserved() / 2**30, 3)}
    checks = smoke_checks(record) if mode == D.SMOKE else {}
    record["smoke_checks"] = checks
    record["outcome"] = ("SMOKE_PASSED" if checks and all(checks.values()) else
                         "SMOKE_FAILED" if checks else "TRAINED")
    record["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    write_json(os.path.join(out_dir, "run_record.json"), record)
    if args.report_dir:
        write_json(os.path.join(args.report_dir, "run_record.json"), record)
    print("=" * 78)
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"  outcome: {record['outcome']} · total {record['duration_total_s']}s · record {out_dir}/run_record.json")
    if mode == D.SMOKE:
        print("  SMOKE ONLY — this is not a trained V5 model and not evidence of V5 quality.")
    print("=" * 78, flush=True)
    return 0 if record["outcome"] in ("SMOKE_PASSED", "TRAINED") else 2


def _check_training_batch(trainer, record):
    """Inspect one collated batch: labels are -100 outside the completion, and no truncation happened."""
    batch = next(iter(trainer.get_train_dataloader()))
    labels, ids, attn = batch["labels"], batch["input_ids"], batch["attention_mask"]
    ds = trainer.train_dataset
    first = ds[0]
    record["collator_check"] = {
        "batch_shape": list(ids.shape),
        "supervised_tokens_in_batch": int((labels != -100).sum()),
        "attended_tokens_in_batch": int(attn.sum()),
        "dataset_columns": sorted(ds.column_names),
        "first_example_len": len(first["input_ids"]),
        "first_example_supervised": int(sum(first["completion_mask"])),
    }


def completion_logits(model, examples, torch):
    out = []
    with torch.no_grad():
        for e in examples:
            ids = torch.tensor([e["input_ids"]], device=model.device)
            logits = model(input_ids=ids).logits[0]
            out.append(logits[e["prompt_len"] - 1: len(e["input_ids"]) - 1].float().cpu())
    return out


def run_generation(model, tok, recipe, contract, rows, torch) -> dict:
    template, vocab = D.recipe_template(recipe), D.recipe_vocabulary(recipe)
    results = []
    model.config.use_cache = True
    with torch.no_grad():
        for r in rows:
            ids = T.encode_prompt(tok, template, r["text"])
            x = torch.tensor([ids], device=model.device)
            gen = model.generate(input_ids=x, attention_mask=torch.ones_like(x), do_sample=False,
                                 max_new_tokens=contract.label_budget + 4, eos_token_id=tok.eos_token_id,
                                 pad_token_id=tok.eos_token_id)
            new = gen[0, len(ids):].tolist()
            ended = tok.eos_token_id in new
            body = new[: new.index(tok.eos_token_id)] if ended else new
            text = tok.decode(body, skip_special_tokens=True)
            parsed = OC.parse_v5_output(text, vocab, ended_with_eos=ended)
            results.append({"text_sha256": r["meta"]["text_sha256"], "expected": r["output"], "generated": text,
                            "ended_with_eos": ended, "status": parsed.status, "invalid_reason": parsed.invalid_reason,
                            "matches_expected": parsed.status == OC.OK and text.strip() == r["output"]})
    return {"n": len(results), "split": "VALIDATION",
            "status_counts": _count(x["status"] for x in results),
            "ended_with_eos": sum(x["ended_with_eos"] for x in results),
            "matches_expected": sum(x["matches_expected"] for x in results),
            "note": "format check of the pipeline on synthetic fixture rows; NOT a V5 quality metric",
            "results": results}


def loss_stability(losses: list) -> dict:
    finite = all(math.isfinite(x) for x in losses)
    k = max(1, min(5, len(losses) // 4))
    first, last = (sum(losses[:k]) / k, sum(losses[-k:]) / k) if losses else (float("nan"), float("nan"))
    return {"n_logged": len(losses), "all_finite": finite, "first_window_mean": first, "last_window_mean": last,
            "decreased": bool(losses) and last < first, "max": max(losses) if losses else None}


def adapter_inventory(adapter_dir: str) -> dict:
    from safetensors import safe_open
    st = os.path.join(adapter_dir, "adapter_model.safetensors")
    with safe_open(st, "pt") as fh:
        keys = list(fh.keys())
    files = {f: {"bytes": os.path.getsize(os.path.join(adapter_dir, f)),
                 "sha256": D.sha256_file(os.path.join(adapter_dir, f))}
             for f in sorted(os.listdir(adapter_dir)) if os.path.isfile(os.path.join(adapter_dir, f))}
    with open(os.path.join(adapter_dir, "adapter_config.json"), encoding="utf-8") as fh:
        acfg = json.load(fh)
    return {"path": os.path.relpath(adapter_dir, D.REPO_ROOT), "files": files, "tensor_count": len(keys),
            "non_lora_tensors": [k for k in keys if "lora_" not in k],
            "adapter_model_bytes": os.path.getsize(st),
            "adapter_config": {k: acfg.get(k) for k in ("base_model_name_or_path", "revision", "r", "lora_alpha",
                                                        "target_modules", "modules_to_save", "task_type")}}


def smoke_checks(rec: dict) -> dict:
    ls, inf, rl = rec["loss_stability"], rec["inference"], rec["reload"]
    return {
        "1_gpu_available_and_bf16": rec["gpu"]["bf16_supported"],
        "2_tinyllama_loaded_4bit": rec["model_loaded_4bit"],
        "3_forward_backward_ran": ls["n_logged"] > 0 and rec["trainable"]["lora_tensors"] > 0
                                  and not rec["trainable"]["non_lora_trainable"],
        "4_loss_finite_and_decreasing": ls["all_finite"] and ls["decreased"]
                                        and math.isfinite(rec["eval_metrics_validation"].get("eval_loss", float("nan"))),
        "5_adapter_saved_lora_only": rec["adapter"]["tensor_count"] > 0 and not rec["adapter"]["non_lora_tensors"],
        "6_reload_matches_in_memory": all(rl["argmax_identical_on_completion"]) and bool(rl["checkpoint_forward_finite"]),
        "7_inference_strict_format": inf["n"] > 0 and inf["status_counts"].get(OC.OK, 0) == inf["n"],
    }


if __name__ == "__main__":
    sys.exit(main())
