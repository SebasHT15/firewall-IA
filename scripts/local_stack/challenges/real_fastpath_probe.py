"""One app-bound Fast Path wiring probe with real V5.1 and a temporary GPU hand-off.

This is a lab integration check, not a quality, latency or capacity estimate.
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

from scripts.model2.real_guard_probe import ROOT, STATUS, PYTHON, digest, gpu_busy
from scripts.local_stack.challenges import adapters, smoke

CLI = ROOT / "scripts/local_stack/challenges/challenge_stack.py"


def command(*args):
    return [str(PYTHON), "-B", str(CLI), *map(str, args)]


def run(app, out, work):
    if out.exists() or work.exists():
        raise FileExistsError("new output and private work directories required")
    before = json.loads(STATUS.read_text())
    if before.get("state") != "AVAILABLE" or before.get("owner") not in (None, "none") or gpu_busy():
        raise RuntimeError("GPU is not free for the owner-authorized V5.1 probe")
    out.mkdir(parents=True)
    work.mkdir(parents=True)
    (out / "GPU_STATUS.before.json").write_text(json.dumps(before, indent=2) + "\n")
    nonce = secrets.token_hex(12)
    STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE_FOR_CLAUDE",
                                  "handoff_id": nonce, "UTC": time.time(),
                                  "note": "Sebas authorized temporary real V5.1 integration testing; "
                                          "Fast Path lab probe, 2026-11-05"}, indent=2) + "\n")
    config = out / f"{app}.guarded.fast-path.stack.json"
    try:
        cfg = subprocess.run(command("config", "--app", app, "--arm", "guarded", "--fast-path",
                                     "--out", config), cwd=ROOT, capture_output=True, text=True, timeout=30)
        if cfg.returncode:
            raise RuntimeError(f"config failed: {cfg.stderr[-300:]}")
        log = out / "up.stdout.txt"
        with log.open("x") as handle:
            up = subprocess.run(command("up", "--app", app, "--arm", "guarded", "--config", config,
                                        "--work", work, "--v5", "real"), cwd=ROOT,
                                stdout=handle, stderr=subprocess.STDOUT, timeout=600)
        if up.returncode:
            raise RuntimeError(f"real V5.1 stack startup failed; see {log}")
        state = json.loads((work / "stack-state.json").read_text())
        if state.get("v5") != "real" or state["identity"].get("fast_path") is None:
            raise RuntimeError("real V5.1 or pinned Fast Path identity missing")
        front = smoke.Front(state)
        observed = []
        for target, expected_stage in ((adapters.FAST_PATH_STATIC[app], "fast_path"), ("/", "v5")):
            snap = smoke.snapshot(state)
            status, body = front.tls("GET", target)
            time.sleep(0.5)
            attr = smoke.attribution(state, target, snap)
            decision = attr["gateway_last_decision"] or {}
            if (decision.get("deciding_stage") != expected_stage
                    or (expected_stage == "fast_path" and
                        (decision.get("model2") is not None or decision.get("v5") is not None))):
                raise RuntimeError(f"wrong stage for {target}: {decision.get('deciding_stage')}")
            observed.append({"target": target, "status": status, "body_len": len(body),
                             "stage": decision["deciding_stage"],
                             "fast_path": decision.get("fast_path"),
                             "model2_decision": (decision.get("model2") or {}).get("decision"),
                             "v5_decision": (decision.get("v5") or {}).get("decision"),
                             "app_received": attr["app_received"]})
        result = {"schema": "challenge-fastpath-real-v51-probe/v1", "scope": "LAB_INTEGRATION_ONLY",
                  "app": app, "apps_commit": state["apps_commit"], "v5": "real", "status": "COMPLETE",
                  "config_sha256": digest(config), "policy_sha256": state["identity"]["fast_path"]["policy_sha256"],
                  "observed": observed, "source_sha256": digest(Path(__file__))}
        (out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result
    finally:
        if (work / "stack-state.json").exists():
            subprocess.run(command("down", "--work", work), cwd=ROOT, capture_output=True, text=True)
            clean = subprocess.run(command("check-clean", "--work", work), cwd=ROOT,
                                   capture_output=True, text=True)
            (out / "CLEAN.json").write_text(clean.stdout)
        current = json.loads(STATUS.read_text())
        if current.get("handoff_id") == nonce:
            STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE", "UTC": time.time(),
                                          "note": "Owner-authorized V5.1 Fast Path probe ended; GPU released"},
                                         indent=2) + "\n")
        (out / "GPU_STATUS.after.json").write_text(STATUS.read_text())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=adapters.APP_NAMES, default="ObC00ki3s")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.app, args.out.resolve(), args.work.resolve()), indent=2))
