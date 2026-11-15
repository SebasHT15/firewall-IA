"""Run paired local-stack demos with real V5.1 under an owner-authorized GPU hand-off.

The application traffic is an authored lab walkthrough. This checks identity,
live decisions, and cleanup; it is not an independent quality or load census.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
STATUS = Path("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json")
PYTHON = ROOT / ".venv-dataplane/bin/python"
CONFIGS = {
    "v51_only": ROOT / "reports/v5/model2-defer-only-2026-11-05/v51-only.stack.json",
    "guarded": ROOT / "reports/v5/model2-guarded-2026-11-05/v51-model2-guarded.stack.json",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def gpu_busy():
    proc = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                           "--format=csv,noheader,nounits"], text=True, capture_output=True, check=True)
    for line in proc.stdout.splitlines():
        fields = [part.strip() for part in line.rsplit(",", 2)]
        if len(fields) == 3 and fields[2].isdigit() and int(fields[2]) >= 300:
            return True
    return False


def command(*args):
    return [str(PYTHON), "-B", *map(str, args)]


def run(out, work):
    if out.exists() or work.exists():
        raise FileExistsError("new output and private work directories required")
    before = json.loads(STATUS.read_text())
    if before.get("state") != "AVAILABLE" or before.get("owner") not in (None, "none") or gpu_busy():
        raise RuntimeError("GPU is not free for the owner-authorized hand-off")
    out.mkdir(parents=True)
    work.mkdir(parents=True)
    (out / "GPU_STATUS.before.json").write_text(json.dumps(before, indent=2) + "\n")
    nonce = secrets.token_hex(12)
    STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE_FOR_CLAUDE",
                                  "handoff_id": nonce, "UTC": time.time(),
                                  "note": "Sebas authorized Codex to run the Claude local stack with real V5.1; "
                                          "temporary test hand-off, 2026-11-05"}, indent=2) + "\n")
    completed = {}
    try:
        for name, config in CONFIGS.items():
            arm_work = work / name
            result = out / f"{name}.json"
            log = out / f"{name}.stdout.txt"
            with log.open("x") as handle:
                proc = subprocess.run(command("scripts/local_stack/demo.py", "--config", config,
                                              "--work", arm_work, "--v5", "real", "--json", result),
                                      cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, timeout=900)
            if proc.returncode != 0:
                raise RuntimeError(f"{name} demo failed; see {log}")
            clean = subprocess.run(command("scripts/local_stack/stack.py", "check-clean", "--work", arm_work),
                                   cwd=ROOT, text=True, capture_output=True, check=True)
            if json.loads(clean.stdout).get("clean") is not True:
                raise RuntimeError(f"{name} left components running")
            document = json.loads(result.read_text())
            if document.get("v5") != "real" or len(document.get("rows", [])) != 12:
                raise RuntimeError(f"{name} real demo incomplete")
            completed[name] = {"config_sha256": digest(config), "result_sha256": digest(result),
                               "log_sha256": digest(log), "clean": True,
                               "observed": [{"step": r["step"], "path": r["path"],
                                             "status": r["observed"][0], "layer": r["observed"][1],
                                             "stage": r["gateway"][0]["stage"] if r["gateway"] else None}
                                            for r in document["rows"]]}
        summary = {"schema": "model2-guarded-real-v51-demo/v1", "scope": "AUTHORED_LAB_WALKTHROUGH",
                   "status": "COMPLETE", "arms": completed,
                   "source_sha256": digest(Path(__file__)),
                   "protected_opened": False, "candidate_selected": None}
        (out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return summary
    finally:
        for name in CONFIGS:
            arm_work = work / name
            if (arm_work / "stack-state.json").exists():
                subprocess.run(command("scripts/local_stack/stack.py", "down", "--work", arm_work),
                               cwd=ROOT, capture_output=True, text=True)
        current = json.loads(STATUS.read_text())
        if current.get("handoff_id") == nonce:
            STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE", "UTC": time.time(),
                                          "note": "Owner-authorized V5.1 real probe ended; GPU released"}, indent=2) + "\n")
        (out / "GPU_STATUS.after.json").write_text(STATUS.read_text())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.out.resolve(), args.work.resolve()), indent=2))
