#!/usr/bin/env python3
"""V5 GPU launch preflight — a read-only diagnostic that says whether the TARGET environment is ready to
run the (future) V5 fine-tune, and leaves the exact reproducible command ready.

It CHECKS (never trains, never loads weights onto the GPU, never downloads a model, never reads a dataset
row or a protected evaluation):
  * interpreter version vs the recipe's `library_pins.python`;
  * every pinned library's EFFECTIVE version vs the recipe (same `startswith` rule the trainer's F9 uses);
  * GPU / CUDA / VRAM (torch device *properties* and free memory — no tensor is allocated) with an
    `nvidia-smi` fallback;
  * free disk at the output root;
  * the pinned base model + tokenizer present LOCALLY in the HF cache (file presence only; `local_files_only`);
  * recipe ratification status, via `v5_train_data.unratified_recipe_sections` (the trainer's own API — no
    parallel admission criteria). D71 ratified template/vocabulary/token_budget; the rest stay PROPOSED.
  * OPTIONALLY, when the (future) dataset manifest / preregistration / freeze / authorizations are passed,
    the trainer's FINAL gate `v5_train_data.gate_final` on the MANIFEST METADATA — it reads manifest.json /
    recipe / the record files, never the dataset rows.

It PRODUCES a JSON report with per-check `ok` + closed rejection reasons, a measured-vs-estimated resource
section, and the exact `finetune_v5.py` command (verified against its real flags). Preparing a launch is
NOT training and NOT a ratification; missing resources are reported with the concrete file/field.

Run it with the TRAINING interpreter so the version/GPU checks are meaningful:
  /usr/bin/python3.12 scripts/training/v5_launch_preflight.py \
      [--dataset DIR --dataset-prereg P --freeze-record F --training-prereg T --ai-audit-authorization A] \
      [--out report.json]
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import shutil
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import finetune_v5 as FV  # noqa: E402
import v5_train_data as D  # noqa: E402  (reuse the trainer's gate APIs; never edited)

DEFAULT_RECIPE = os.path.join(HERE, "v5_training_recipe_v1.json")
PINNED_LIBS = ("torch", "transformers", "trl", "peft", "bitsandbytes", "datasets", "accelerate")


def _ok(ok, detail, **extra):
    return {"ok": bool(ok), "detail": detail, **extra}


def check_interpreter(recipe) -> dict:
    want = str(recipe["library_pins"].get("python", ""))
    got = ".".join(map(str, sys.version_info[:2]))
    return _ok(got == want or (want and got.startswith(want)), f"python {got}", pinned=want, running=got)


def check_libraries(recipe) -> dict:
    pins, results, all_ok = recipe["library_pins"], {}, True
    for lib in PINNED_LIBS:
        pin = str(pins.get(lib, ""))
        try:
            got = md.version(lib)
        except md.PackageNotFoundError:
            got = None
        ok = got is not None and str(got).startswith(pin)      # same rule as gate_final F9
        all_ok = all_ok and ok
        results[lib] = {"ok": ok, "installed": got, "pinned": pin}
    return _ok(all_ok, "pinned libraries vs installed", libraries=results)


def check_gpu() -> dict:
    info = {"torch_cuda": None, "devices": [], "nvidia_smi": None}
    try:
        import torch
        info["torch_version"] = torch.__version__
        info["torch_cuda"] = bool(torch.cuda.is_available())
        if torch.cuda.is_available():
            for i in range(torch.cuda.device_count()):
                p = torch.cuda.get_device_properties(i)                 # properties only; no allocation
                free, total = torch.cuda.mem_get_info(i)
                info["devices"].append({"index": i, "name": p.name,
                                        "total_MiB": round(p.total_memory / 2**20),
                                        "free_MiB": round(free / 2**20),
                                        "capability": f"{p.major}.{p.minor}"})
    except Exception as e:                                              # noqa: BLE001 — torch may be absent
        info["torch_error"] = f"{type(e).__name__}: {e}"
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,memory.free,driver_version",
                              "--format=csv,noheader"], capture_output=True, text=True, timeout=15)
        if out.returncode == 0:
            info["nvidia_smi"] = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    except Exception as e:                                             # noqa: BLE001
        info["nvidia_smi_error"] = f"{type(e).__name__}"
    ok = bool(info.get("torch_cuda")) and bool(info["devices"])
    reason = None if ok else "no CUDA device visible to torch (or torch absent); a GPU is required for V5"
    return _ok(ok, "GPU / CUDA / VRAM", reason=reason, **info)


def check_disk(path=REPO_ROOT, need_gib=20) -> dict:
    try:
        free_gib = shutil.disk_usage(path).free / 2**30
    except OSError as e:
        return _ok(False, f"disk_usage failed: {type(e).__name__}", reason="cannot stat output filesystem")
    return _ok(free_gib >= need_gib, f"{free_gib:.1f} GiB free at {path}",
               free_GiB=round(free_gib, 1), need_GiB_estimate=need_gib,
               reason=None if free_gib >= need_gib else f"< {need_gib} GiB free")


def _hf_cache_dir():
    for env in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"):
        if os.environ.get(env):
            return os.environ[env]
    home = os.environ.get("HF_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "huggingface")
    return os.path.join(home, "hub")


def check_base_model(recipe) -> dict:
    name = recipe["base_model"]["name"]
    rev = recipe["base_model"]["revision"]
    cache = _hf_cache_dir()
    repo_dir = os.path.join(cache, "models--" + name.replace("/", "--"))
    snap = os.path.join(repo_dir, "snapshots", rev)
    present = os.path.isdir(snap)
    files = sorted(os.listdir(snap)) if present else []
    has_weights = any(f.endswith((".safetensors", ".bin")) for f in files)
    has_tokenizer = any(f in files for f in ("tokenizer.json", "tokenizer.model"))
    ok = present and has_weights and has_tokenizer
    reason = None
    if not present:
        reason = f"snapshot not in local HF cache: {os.path.relpath(snap, os.path.expanduser('~'))}"
    elif not (has_weights and has_tokenizer):
        reason = f"snapshot present but missing {'weights' if not has_weights else 'tokenizer'}"
    return _ok(ok, f"{name}@{rev[:12]} local_files_only", reason=reason,
               cache=cache, snapshot_present=present, has_weights=has_weights, has_tokenizer=has_tokenizer)


def check_recipe_ratification(recipe) -> dict:
    unrat = dict(D.unratified_recipe_sections(recipe))      # trainer API; D71 ratified template/vocab/token_budget
    ratified = [s for s in (("recipe",) + D.RECIPE_SECTIONS) if s not in unrat]
    # Not a launch blocker for ENV readiness, but FINAL needs these ratified (reported, never auto-marked).
    return _ok(not unrat, "recipe sections ratified (D71 + pending)", ratified=sorted(ratified),
               not_ratified=dict(unrat), note="FINAL requires all RATIFIED; this preflight never marks them")


def check_final_gate(args, recipe, recipe_sha) -> dict:
    """OPTIONAL: the trainer's FINAL gate on the manifest METADATA (no dataset row is read). Skipped unless
    a --dataset is given (the dataset/records are what Codex is finishing)."""
    if not args.dataset:
        return {"ok": None, "detail": "skipped: no --dataset (dataset/preregistration/freeze/authorizations "
                                      "are the pending inputs)", "skipped": True}
    manifest_path = os.path.join(args.dataset, "manifest.json")
    if not os.path.isfile(manifest_path):
        return _ok(False, f"no manifest.json in {args.dataset}", reason="dataset manifest missing")
    manifest, msha = D.load_manifest(args.dataset)
    versions = FV.installed_versions()  # includes Python, like the real F9 gate
    metadata_out = os.path.join(D.OUTPUT_ROOT,'final','PREFLIGHT_METADATA_ONLY')
    diags = D.gate_common(args.dataset,manifest,D.FINAL,metadata_out)
    diags += D.protected_split_declared_diags(manifest)
    diags += D.gate_final(manifest, msha, recipe, recipe_sha, dataset_prereg=args.dataset_prereg,
                         freeze_record=args.freeze_record, training_prereg=args.training_prereg,
                         installed_versions=versions, git=D.git_state(),
                         code_paths=FV.CODE_FILES+(os.path.abspath(args.recipe),), ai_audit_authorization=args.ai_audit_authorization)
    return _ok(not diags, "trainer FINAL gate on manifest metadata (no rows read)",
               unmet=[d.as_dict() for d in diags])


def _installed(lib):
    try:
        md.version(lib)
        return True
    except md.PackageNotFoundError:
        return False


def estimate_resources(recipe) -> dict:
    """MEASURED vs ESTIMATED. The VRAM figure is a rough estimate for a ~1.1B QLoRA (nf4) fine-tune, not a
    measurement; the only measured GPU numbers are in `checks.gpu`."""
    q = recipe.get("quantization", {})
    return {"estimated_peak_vram_GiB": "~4-8 (ESTIMATE: 1.1B nf4 4-bit base + LoRA + paged_adamw_8bit "
                                       "optimizer states + activations at the recipe batch/accum; not measured)",
            "estimate_basis": {"base_params": "~1.1B", "load_in_4bit": q.get("load_in_4bit"),
                               "compute_dtype": q.get("bnb_4bit_compute_dtype")},
            "note": "A measurement requires actually loading the model (out of scope: preflight loads no weights)."}


def check_schedule(args, recipe, gpu_devices) -> dict:
    """The effective training SCHEDULE (via `finetune_v5.compute_schedule`), computed from the manifest's
    TRAIN|split count (METADATA, no rows) and the measured GPU count. Skipped without --dataset; the trainer
    re-derives it from the exact eligible TRAIN count at run time and records it before training."""
    num_devices = max(1, len(gpu_devices or []))
    if not args.dataset:
        return {"ok": None, "skipped": True, "num_devices": num_devices,
                "detail": "no --dataset: the trainer fixes+records the schedule from the eligible TRAIN count "
                          "before training (finetune_v5.compute_schedule)"}
    mpath = os.path.join(args.dataset, "manifest.json")
    if not os.path.isfile(mpath):
        return _ok(False, "no manifest.json", reason="dataset manifest missing")
    try:
        manifest, _ = D.load_manifest(args.dataset)
    except (OSError, ValueError) as e:
        return _ok(False, f"manifest unreadable: {type(e).__name__}")
    train_rows = int((manifest.get("counts", {}).get("by_split_disposition", {}) or {}).get("TRAIN|split", 0))
    sched = FV.compute_schedule(recipe, train_rows, num_devices)
    return _ok(train_rows > 0, "effective schedule from manifest TRAIN count (metadata, no rows)",
               source="manifest.counts.by_split_disposition['TRAIN|split']", schedule=sched,
               reason=None if train_rows > 0 else "manifest records no TRAIN|split rows")


def train_command(recipe_path, dataset='<DATASET_DIR>', run_id='<RUN_ID>', *,
                  dataset_prereg='<PREREG>',freeze_record='<FREEZE>',training_prereg='<TRAIN_PREREG>',
                  ai_audit_authorization='<AI_AUTH>') -> dict:
    """Shell-quoted CLI plus structured argv. Gate reports must not create the training output dir."""
    out_dir = os.path.join('model-output-v5','final',run_id)
    report_dir = os.path.join('model-output-v5','gate-reports',run_id)
    argv = ['/usr/bin/python3.12','scripts/training/finetune_v5.py','--mode','final',
            '--dataset',dataset,'--recipe',os.path.abspath(recipe_path),
            '--dataset-prereg',dataset_prereg,'--freeze-record',freeze_record,
            '--training-prereg',training_prereg,'--run-id',run_id,'--report-dir',report_dir]
    if ai_audit_authorization:
        argv += ['--ai-audit-authorization',ai_audit_authorization]
    return {'gate_only_first':shlex.join(argv+['--gate-only']),'final_run':shlex.join(argv),
            'gate_only_argv':argv+['--gate-only'],'final_argv':argv,'output_dir':out_dir,
            'report_dir':report_dir,
            'artifacts':{'adapter':os.path.join(out_dir,'adapter'),
                         'checkpoints':os.path.join(out_dir,'checkpoints'),
                         'run_record':os.path.join(out_dir,'run_record.json')},
            'resume':'no --resume CLI flag exists; checkpoints are retained; existing output dirs are refused',
            'flags_verified_against':'scripts/training/finetune_v5.py:parse_args'}


def run(args) -> dict:
    recipe, recipe_sha = D.load_recipe(args.recipe)
    checks = {
        "interpreter": check_interpreter(recipe),
        "libraries": check_libraries(recipe),
        "gpu": check_gpu(),
        "disk": check_disk(),
        "base_model": check_base_model(recipe),
        "recipe_ratification": check_recipe_ratification(recipe),
        "final_gate": check_final_gate(args, recipe, recipe_sha),
    }
    checks["schedule"] = check_schedule(args, recipe, checks["gpu"].get("devices"))
    env_keys = ("interpreter", "libraries", "gpu", "disk", "base_model")
    env_ready = all(checks[k]["ok"] for k in env_keys)
    pending = []
    if not checks["recipe_ratification"]["ok"]:
        pending.append({"resource": "recipe ratification", "detail": checks["recipe_ratification"]["not_ratified"]})
    if checks["final_gate"].get("skipped"):
        pending.append({"resource": "dataset + preregistration + freeze + authorizations",
                        "detail": "pass --dataset/--dataset-prereg/--freeze-record/--training-prereg"
                                  "[/--ai-audit-authorization] once Codex's emitter/pools produce them"})
    elif checks["final_gate"].get("unmet"):
        pending.append({"resource": "FINAL gate conditions", "detail": checks["final_gate"]["unmet"]})
    report = {
        "schema": "v5-launch-preflight/v1",
        "env_ready": env_ready,
        "ready_to_launch": False,
        "ready_for_trainer_gate_only": env_ready and checks['final_gate']['ok'] is True,
        "launch_readiness_scope": "metadata only; the real trainer --gate-only must verify eligible row bytes before training",
        "checks": checks,
        "resources": {"measured_gpu": checks["gpu"].get("devices"),
                      "measured_disk_free_GiB": checks["disk"].get("free_GiB"),
                      "estimated": estimate_resources(recipe)},
        "train_command": train_command(args.recipe,dataset=(args.dataset or '<DATASET_DIR>'),
            run_id=getattr(args,'run_id','<RUN_ID>'),dataset_prereg=args.dataset_prereg or '<PREREG>',
            freeze_record=args.freeze_record or '<FREEZE>',training_prereg=args.training_prereg or '<TRAIN_PREREG>',
            ai_audit_authorization=args.ai_audit_authorization or '<AI_AUTH>'),
        "pending": pending,
        "disclaimers": ["No weights loaded, no model downloaded, no dataset row or protected evaluation read.",
                        "Preparing a launch is not training and not a ratification (D71 only). RATIFIED is never "
                        "set and no authorization is signed here."],
        "recipe_sha256": recipe_sha,
    }
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--recipe", default=DEFAULT_RECIPE)
    ap.add_argument("--dataset", default=None, help="stage-4 generator output dir (manifest only is read; no rows)")
    ap.add_argument("--dataset-prereg", default=None)
    ap.add_argument("--freeze-record", default=None)
    ap.add_argument("--training-prereg", default=None)
    ap.add_argument("--ai-audit-authorization", default=None)
    ap.add_argument("--run-id", default="<RUN_ID>")
    ap.add_argument("--out", default=None, help="write the JSON report here (also printed to stdout)")
    args = ap.parse_args(argv)
    report = run(args)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0 if report["env_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
