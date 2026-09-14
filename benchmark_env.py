"""
firewall-IA — experiment environment manifest (Issue #9).

Captures what the benchmark actually ran on, read from THIS machine at THIS
moment. Nothing here is copied from documentation, from `requirements.txt` or
from an earlier report: every value is queried live, and anything that cannot be
queried is recorded as `null` with a reason rather than guessed.

Two version numbers are deliberately kept apart:

  * `gpu.driver_max_cuda_version` — the highest CUDA the NVIDIA driver reports
    it can support (`nvidia-smi`). This is a compatibility ceiling.
  * `python.torch_cuda_runtime` — the CUDA runtime PyTorch was actually built
    against and is actually using.

They are routinely different (here 13.2 vs 12.4) and confusing them
misattributes the runtime.

No secrets: the process environment is not dumped. Only a fixed allowlist of
variables that change benchmark behaviour is recorded.

Used by `benchmark_inference.py`; safe to run standalone:

    python3.12 benchmark_env.py
"""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Only these environment variables are recorded. Anything else — tokens, keys,
# proxies, credentials — is never read or written to a manifest.
ENV_ALLOWLIST = (
    "FIREWALL_ADAPTER_DIR",
    "CUDA_VISIBLE_DEVICES",
    "CUDA_DEVICE_ORDER",
    "PYTHONHASHSEED",
    "OMP_NUM_THREADS",
    "TOKENIZERS_PARALLELISM",
)

# Packages whose exact installed version can move a latency number. Recorded
# from the live interpreter, not from requirements.txt.
TRACKED_PACKAGES = (
    "torch", "transformers", "peft", "accelerate", "bitsandbytes",
    "tokenizers", "safetensors", "numpy", "trl", "datasets",
    "fastapi", "pydantic", "uvicorn",
)

UNAVAILABLE = "<unavailable>"


# ── Shell helpers ──────────────────────────────────────────────────────────
def _run(cmd, timeout=20, strip=True):
    """Run a command, return stdout, or None if it cannot be run.

    `strip=False` for column-aligned output such as `git status --porcelain`,
    whose leading space is part of the status code.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() if strip else r.stdout


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def sha256_file(path):
    """SHA-256 of a file, or None if it cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Code identity ──────────────────────────────────────────────────────────
def code_state():
    """Identify the code that is about to run — reproducibly, even if dirty.

    A clean tree is fully identified by its commit. A dirty tree is not, so the
    uncommitted diff is hashed and its size recorded: two runs of the same dirty
    tree produce the same `working_tree_diff_sha256`, and a run whose diff hash
    differs from a report's is provably different code. The diff itself is NOT
    embedded — it can contain arbitrary content.

    The files that define the measured path are hashed individually as well, so
    a report can be checked against them without a git checkout.
    """
    git = ["git", "-C", REPO_ROOT]
    commit = _run(git + ["rev-parse", "HEAD"]) or UNAVAILABLE
    branch = _run(git + ["rev-parse", "--abbrev-ref", "HEAD"]) or UNAVAILABLE
    porcelain = _run(git + ["status", "--porcelain"], strip=False)
    lines = [l for l in (porcelain or "").splitlines() if l.strip()]
    dirty = bool(lines)

    diff_sha, diff_bytes, changed = None, None, []
    if dirty:
        # Tracked modifications only; untracked files are not in `git diff`.
        diff = _run(git + ["diff", "HEAD"], strip=False) or ""
        diff_sha = sha256_text(diff)
        diff_bytes = len(diff.encode("utf-8"))
        # "XY path" — the two status columns, a space, then the path.
        changed = sorted(f"{l[:2]} {l[2:].strip()}" for l in lines)

    measured_sources = {}
    for name in ("inference_core.py", "benchmark_inference.py", "benchmark_env.py",
                 "benchmark_compare.py", "test_model.py"):
        p = os.path.join(REPO_ROOT, name)
        if os.path.exists(p):
            measured_sources[name] = sha256_file(p)

    return {
        "repo_root": REPO_ROOT,
        "git_commit": commit,
        "git_branch": branch,
        "working_tree_clean": not dirty,
        "working_tree_changed_paths": changed,
        "working_tree_diff_sha256": diff_sha,
        "working_tree_diff_bytes": diff_bytes,
        "measured_source_sha256": measured_sources,
        "note": ("A clean tree is identified by git_commit alone. When dirty, "
                 "git_commit + working_tree_diff_sha256 identify the executed "
                 "code; the diff content is not stored."),
    }


# ── Operating system ───────────────────────────────────────────────────────
def os_state():
    rel = {}
    raw = _read("/etc/os-release") or ""
    for line in raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            rel[k] = v.strip('"')
    return {
        "distribution": rel.get("PRETTY_NAME") or UNAVAILABLE,
        "distribution_id": rel.get("ID"),
        "distribution_version": rel.get("VERSION_ID"),
        "distribution_codename": rel.get("VERSION_CODENAME"),
        "kernel_release": platform.release(),
        "kernel_version": platform.version(),
        "machine": platform.machine(),
        "hostname_recorded": False,
        "hostname_note": "Deliberately not recorded — identifies the operator's machine.",
    }


# ── CPU / RAM ──────────────────────────────────────────────────────────────
def cpu_state():
    model, cores, threads = None, None, None
    cpuinfo = _read("/proc/cpuinfo") or ""
    for line in cpuinfo.splitlines():
        if line.startswith("model name") and model is None:
            model = line.partition(":")[2].strip()
    threads = os.cpu_count()

    lscpu = _run(["lscpu"]) if shutil.which("lscpu") else None
    sockets = cores_per_socket = None
    if lscpu:
        for line in lscpu.splitlines():
            if line.startswith("Core(s) per socket:"):
                cores_per_socket = int(line.partition(":")[2].strip())
            elif line.startswith("Socket(s):"):
                sockets = int(line.partition(":")[2].strip())
    if cores_per_socket and sockets:
        cores = cores_per_socket * sockets

    governors = set()
    try:
        base = "/sys/devices/system/cpu"
        for entry in sorted(os.listdir(base)):
            if re.fullmatch(r"cpu\d+", entry):
                g = _read(os.path.join(base, entry, "cpufreq", "scaling_governor"))
                if g:
                    governors.add(g)
    except OSError:
        pass

    return {
        "model": model or UNAVAILABLE,
        "physical_cores": cores,
        "logical_cpus": threads,
        "scaling_governors": sorted(governors) or None,
        "scaling_governor_note": (None if governors else
                                  "cpufreq scaling_governor not exposed on this system"),
    }


def memory_state():
    meminfo = _read("/proc/meminfo") or ""
    out = {}
    for key, field in (("MemTotal:", "ram_total_kb"), ("MemAvailable:", "ram_available_kb"),
                       ("SwapTotal:", "swap_total_kb")):
        for line in meminfo.splitlines():
            if line.startswith(key):
                out[field] = int(line.split()[1])
                break
    total = out.get("ram_total_kb")
    out["ram_total_gib"] = round(total / (1024 ** 2), 2) if total else None
    return out


# ── GPU ────────────────────────────────────────────────────────────────────
def _nvidia_query(fields):
    """One `nvidia-smi --query-gpu` call. Returns a list of dicts, one per GPU."""
    if not shutil.which("nvidia-smi"):
        return None
    out = _run(["nvidia-smi", f"--query-gpu={','.join(fields)}",
                "--format=csv,noheader,nounits"])
    if out is None:
        return None
    rows = []
    for line in out.splitlines():
        vals = [v.strip() for v in line.split(",")]
        if len(vals) == len(fields):
            rows.append(dict(zip(fields, vals)))
    return rows or None


def gpu_state():
    """Static GPU identity. Volatile readings (power, temperature) live in
    `runtime_conditions()` because they are sampled, not fixed."""
    state = {
        "driver_version": None,
        "driver_max_cuda_version": None,
        "driver_max_cuda_note": ("Highest CUDA the driver can support — a "
                                 "compatibility ceiling, NOT the runtime in use. "
                                 "See python.torch_cuda_runtime."),
        "devices": [],
        "available": False,
        "unavailable_reason": None,
    }

    rows = _nvidia_query(["name", "driver_version", "memory.total", "pci.bus_id",
                          "persistence_mode", "power.limit", "enforced.power.limit",
                          "compute_mode"])
    if rows:
        state["driver_version"] = rows[0].get("driver_version")
        for r in rows:
            state["devices"].append({
                "name": r.get("name"),
                "vram_total_mib": _to_num(r.get("memory.total")),
                "pci_bus_id": r.get("pci.bus_id"),
                "persistence_mode": r.get("persistence_mode"),
                "power_limit_w": _to_num(r.get("power.limit")),
                "enforced_power_limit_w": _to_num(r.get("enforced.power.limit")),
                "power_limit_note": ("power.limit reads [N/A] on some laptop GPUs "
                                     "where the cap is dynamic; enforced.power.limit "
                                     "is the value actually in force at capture."),
                "compute_mode": r.get("compute_mode"),
            })
        smi = _run(["nvidia-smi"])
        if smi:
            m = re.search(r"CUDA Version:\s*([0-9.]+)", smi)
            if m:
                state["driver_max_cuda_version"] = m.group(1)
    else:
        state["unavailable_reason"] = "nvidia-smi not present or returned no GPU"

    try:
        import torch
        state["available"] = bool(torch.cuda.is_available())
        if state["available"]:
            props = torch.cuda.get_device_properties(0)
            state["torch_device_0"] = {
                "name": props.name,
                "total_memory_mib": round(props.total_memory / (1024 ** 2), 1),
                "capability": f"{props.major}.{props.minor}",
                "multi_processor_count": props.multi_processor_count,
            }
            if not state["unavailable_reason"] and not state["devices"]:
                state["unavailable_reason"] = None
        else:
            state["unavailable_reason"] = (state["unavailable_reason"]
                                           or "torch.cuda.is_available() is False")
    except Exception as exc:  # torch missing or broken — record, do not crash
        state["unavailable_reason"] = f"torch CUDA query failed: {type(exc).__name__}"
    return state


def _to_num(v):
    if v is None:
        return None
    try:
        f = float(v)
    except ValueError:
        return None
    return int(f) if f.is_integer() else f


# ── Python / packages ──────────────────────────────────────────────────────
def python_state():
    state = {
        "executable": sys.executable,
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "torch_cuda_runtime": None,
        "torch_cuda_runtime_note": ("CUDA runtime PyTorch is built against and "
                                    "actually uses — distinct from the driver's "
                                    "maximum supported CUDA version."),
        "cudnn_version": None,
        "packages_installed": {},
        "packages_note": ("Read from the live interpreter via importlib.metadata. "
                          "null means the package is not installed here."),
    }
    try:
        import torch
        state["torch_cuda_runtime"] = torch.version.cuda
        try:
            state["cudnn_version"] = torch.backends.cudnn.version()
        except Exception:
            state["cudnn_version"] = None
    except Exception:
        pass

    from importlib.metadata import PackageNotFoundError, version as pkg_version
    for name in TRACKED_PACKAGES:
        try:
            state["packages_installed"][name] = pkg_version(name)
        except PackageNotFoundError:
            state["packages_installed"][name] = None
    # torch's +cuXXX local version tag is the part that matters and is not
    # always present in the metadata version string.
    try:
        import torch
        state["packages_installed"]["torch"] = torch.__version__
    except Exception:
        pass
    return state


# ── Model identity ─────────────────────────────────────────────────────────
def _hf_cache_revision(repo_id):
    """Resolve the snapshot revision of a cached HuggingFace repo.

    Returns the commit sha the local snapshot points at, so the base model is
    pinned by revision rather than by a moving repo name.
    """
    home = os.environ.get("HF_HOME") or os.path.join(os.path.expanduser("~"), ".cache",
                                                     "huggingface")
    hub = os.path.join(home, "hub")
    folder = "models--" + repo_id.replace("/", "--")
    snapshots = os.path.join(hub, folder, "snapshots")
    try:
        revs = sorted(os.listdir(snapshots))
    except OSError:
        return None, None
    if not revs:
        return None, None
    ref_main = _read(os.path.join(hub, folder, "refs", "main"))
    rev = ref_main if ref_main in revs else revs[-1]
    return rev, os.path.join(snapshots, rev)


def model_state(adapter_dir, base_model):
    """Identity of base model, tokenizer and adapter — revisions and hashes."""
    state = {
        "base_model_repo": base_model,
        "base_model_revision": None,
        "base_model_weight_sha256": {},
        "adapter_dir": adapter_dir,
        "adapter_config": None,
        "adapter_file_sha256": {},
        "tokenizer_file_sha256": {},
        "notes": [],
    }

    rev, snap = _hf_cache_revision(base_model)
    state["base_model_revision"] = rev
    if snap:
        for fn in sorted(os.listdir(snap)):
            if fn.endswith((".safetensors", ".bin")):
                state["base_model_weight_sha256"][fn] = sha256_file(os.path.join(snap, fn))
    else:
        state["notes"].append(
            "Base model snapshot not found in the local HuggingFace cache; "
            "revision and weight hashes unavailable.")

    if os.path.isdir(adapter_dir):
        cfg_path = os.path.join(adapter_dir, "adapter_config.json")
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
            state["adapter_config"] = {
                k: cfg.get(k) for k in
                ("base_model_name_or_path", "peft_type", "task_type", "r",
                 "lora_alpha", "lora_dropout", "target_modules", "bias",
                 "fan_in_fan_out", "inference_mode", "revision")
                if k in cfg
            }
        except (OSError, ValueError):
            state["notes"].append("adapter_config.json missing or unreadable")

        for fn in sorted(os.listdir(adapter_dir)):
            full = os.path.join(adapter_dir, fn)
            if not os.path.isfile(full):
                continue
            if fn.startswith("tokenizer") or fn == "chat_template.jinja":
                state["tokenizer_file_sha256"][fn] = sha256_file(full)
            elif fn.endswith((".safetensors", ".bin", ".json")):
                state["adapter_file_sha256"][fn] = sha256_file(full)
    else:
        state["notes"].append(f"adapter directory not found: {adapter_dir}")

    return state


def effective_placement(model):
    """Where the loaded model actually ended up — CPU vs GPU, per module.

    Read from the live model object, not assumed from `device_map="auto"`.
    A silent CPU fallback shows up here as CPU-hosted modules.
    """
    out = {"hf_device_map": None, "parameter_devices": {}, "buffers_on_cpu": None,
           "quantization_effective": None}
    try:
        dm = getattr(model, "hf_device_map", None)
        if dm:
            out["hf_device_map"] = {str(k): str(v) for k, v in dm.items()}
        counts = {}
        for _, p in model.named_parameters():
            counts[str(p.device)] = counts.get(str(p.device), 0) + p.numel()
        out["parameter_devices"] = {k: {"parameters": v} for k, v in sorted(counts.items())}
        total = sum(counts.values()) or 1
        for k in out["parameter_devices"]:
            out["parameter_devices"][k]["share"] = round(counts[k] / total, 6)
        out["buffers_on_cpu"] = sum(1 for _, b in model.named_buffers()
                                    if str(b.device) == "cpu")
        qc = getattr(getattr(model, "config", None), "quantization_config", None)
        if qc is not None:
            d = qc.to_dict() if hasattr(qc, "to_dict") else dict(vars(qc))
            out["quantization_effective"] = {k: _jsonable(v) for k, v in d.items()}
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _jsonable(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


# ── Volatile machine conditions ────────────────────────────────────────────
def runtime_conditions(note=""):
    """A sample of the conditions the machine was in — power, thermals, load.

    Volatile by nature: this is a snapshot taken at one instant, not a constant
    of the experiment. Sampled before and after each run so drift is visible.
    """
    cond = {
        "sampled_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": note or None,
        "load_average_1_5_15": None,
        "ac_power": None,
        "battery_capacity_pct": None,
        "gpu": None,
        "other_gpu_processes": None,
    }
    try:
        cond["load_average_1_5_15"] = [round(x, 2) for x in os.getloadavg()]
    except (OSError, AttributeError):
        pass

    # Laptop: on AC or on battery changes clock behaviour materially.
    for supply in ("AC", "ACAD", "ADP0", "ADP1"):
        online = _read(f"/sys/class/power_supply/{supply}/online")
        if online is not None:
            cond["ac_power"] = (online == "1")
            break
    cap = _read("/sys/class/power_supply/BAT0/capacity")
    if cap is not None:
        try:
            cond["battery_capacity_pct"] = int(cap)
        except ValueError:
            pass

    rows = _nvidia_query(["power.draw", "temperature.gpu", "clocks.sm", "clocks.mem",
                          "utilization.gpu", "utilization.memory", "memory.used",
                          "memory.total", "clocks_throttle_reasons.active"])
    if rows:
        cond["gpu"] = [{
            "power_draw_w": _to_num(r.get("power.draw")),
            "temperature_c": _to_num(r.get("temperature.gpu")),
            "clock_sm_mhz": _to_num(r.get("clocks.sm")),
            "clock_mem_mhz": _to_num(r.get("clocks.mem")),
            "utilization_gpu_pct": _to_num(r.get("utilization.gpu")),
            "utilization_memory_pct": _to_num(r.get("utilization.memory")),
            "memory_used_mib": _to_num(r.get("memory.used")),
            "memory_total_mib": _to_num(r.get("memory.total")),
            "throttle_reasons_active": r.get("clocks_throttle_reasons.active"),
        } for r in rows]

    procs = _run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                  "--format=csv,noheader,nounits"]) if shutil.which("nvidia-smi") else None
    if procs is not None:
        entries = []
        for line in procs.splitlines():
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) == 3:
                entries.append({"pid": _to_num(parts[0]), "process_name": parts[1],
                                "used_memory_mib": _to_num(parts[2])})
        cond["other_gpu_processes"] = [e for e in entries if e["pid"] != os.getpid()]
    return cond


# ── Assembly ───────────────────────────────────────────────────────────────
def capture(experiment_id, adapter_dir, base_model, extra=None):
    """Full static environment manifest. Volatile readings are sampled
    separately by `runtime_conditions()` and attached per run."""
    man = {
        "manifest_schema": "firewall-IA/benchmark-env/1",
        "experiment_id": experiment_id,
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "captured_on": "the machine that executed the benchmark",
        "code": code_state(),
        "os": os_state(),
        "cpu": cpu_state(),
        "memory": memory_state(),
        "gpu": gpu_state(),
        "python": python_state(),
        "model": model_state(adapter_dir, base_model),
        "environment_variables": {k: os.environ.get(k) for k in ENV_ALLOWLIST},
        "environment_variables_note": (
            "Allowlist only. The process environment is never dumped, so no "
            "credentials or tokens can reach this file."),
    }
    if extra:
        man.update(extra)
    return man


if __name__ == "__main__":
    import inference_core as core
    doc = capture("adhoc", core.DEFAULT_ADAPTER_DIR, core.BASE_MODEL)
    doc["runtime_conditions_sample"] = runtime_conditions("standalone capture")
    print(json.dumps(doc, indent=2))
