"""Inject one isolated challenge-stack failure and measure restart recovery.

The injection is restricted to this tool's recorded processes/containers.
Every scenario starts with a fresh stack, sends one read-only direct-positive
control, injects one fault, records the response and app delivery, then stops
the old stack and measures clean service after a pinned restart.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(HERE), str(HERE.parent)]

import adapters  # noqa: E402
import smoke  # noqa: E402
import trial  # noqa: E402
from gpu_lease import temporary_handoff  # noqa: E402
from trial_client import TrialClient  # noqa: E402

SCENARIOS = ("v5_down", "model2_down", "app_down", "gateway_down", "front_down")


def component(state, name):
    return next(c for c in state["components"] if c["name"] == name)


def command(*args):
    return [str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
            *map(str, args)]


def launch(args, work, log):
    mapped, _ = trial.config_arm(args.arm)
    with log.open("x") as output:
        result = subprocess.run(command("up", "--app", args.app, "--arm", mapped,
                                        "--config", args.config, "--work", work, "--v5", args.v5),
                                cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        raise RuntimeError("stack startup failed; see private log")
    state = json.loads((work / "stack-state.json").read_text())
    if state["apps_commit"] != adapters.PINNED_APPS_COMMIT or state["v5"] != args.v5:
        raise RuntimeError("running identity differs from pin")
    return state


def shutdown(work, out):
    if not (work / "stack-state.json").exists():
        return
    subprocess.run(command("down", "--work", work), cwd=ROOT, capture_output=True, text=True)
    clean = subprocess.run(command("check-clean", "--work", work), cwd=ROOT,
                           capture_output=True, text=True)
    out.write_text(clean.stdout)
    if clean.returncode or not json.loads(clean.stdout).get("clean"):
        raise RuntimeError("stack resources remain after fault trial")


def request(state, case):
    before = smoke.snapshot(state)
    client = TrialClient(state, "h1_tls_new")
    try:
        t = time.monotonic()
        response = client.request(case["method"], case["target"], case.get("headers", []),
                                  trial.body_bytes(case))
        elapsed = (time.monotonic() - t) * 1000
    finally:
        client.close()
    attr, front = trial.attribute(state, before, case["target"], state["arm"])
    decision = attr.get("gateway_last_decision") or {}
    return {"status": response.get("status"), "complete": response.get("error") is None,
            "elapsed_ms": elapsed, "effect_observed": trial.effect(case["effect_oracle"], response),
            "app_received": attr["app_received"], "gateway_applied": decision.get("applied"),
            "gateway_stage": decision.get("deciding_stage"), "gateway_reason": decision.get("reason"),
            "model2_status": (decision.get("model2") or {}).get("status"),
            "model2_decision": (decision.get("model2") or {}).get("decision"),
            "v5_status": (decision.get("v5") or {}).get("status"),
            "v5_decision": (decision.get("v5") or {}).get("decision"),
            "front_status": (front or {}).get("status"),
            "front_upstream_status": (front or {}).get("upstream_status")}


def inject(state, scenario):
    if scenario in ("app_down", "front_down"):
        name = "app" if scenario == "app_down" else "front"
        container = component(state, name)["container"]
        subprocess.run(["docker", "stop", "-t", "1", container], check=True,
                       capture_output=True, text=True)
        return {"component": name, "action": "stop_recorded_container"}
    if scenario == "model2_down":
        gateway_pid = component(state, "gateway")["pid"]
        children = Path(f"/proc/{gateway_pid}/task/{gateway_pid}/children").read_text().split()
        matches = []
        for pid in children:
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            except OSError:
                continue
            if b"model2_worker.py" in cmdline:
                matches.append(int(pid))
        if len(matches) != 1:
            raise RuntimeError("could not identify exactly one Model2 child of the recorded gateway")
        os.kill(matches[0], signal.SIGKILL)
        return {"component": "model2_worker", "action": "kill_recorded_child"}
    name = "v5-real" if state["v5"] == "real" else "v5-double"
    if scenario == "gateway_down":
        name = "gateway"
    pid = component(state, name)["pid"]
    os.kill(pid, signal.SIGTERM)
    return {"component": name, "action": "terminate_recorded_process"}


def run(args):
    cases = trial.validate_cases(args.cases, args.app)
    case = next((c for c in cases if c["case_id"] == args.case_id), None)
    seal = json.loads(args.seal.read_text())
    if (case is None or case["method"] not in ("GET", "HEAD") or
            case["label"] != "ALLOW" or not case.get("effect_oracle") or
            seal.get("cases_sha256") != trial.sha(args.cases) or seal.get("app") != args.app or
            seal.get("source_sha256") != trial.source_hashes() or
            trial.sha(args.config) != seal["configs"][args.arm]["sha256"]):
        raise ValueError("fault control or seal mismatch")
    if args.scenario == "model2_down" and args.arm not in ("guarded", "guarded_fast"):
        raise ValueError("Model2 fault requires an active cascade arm")
    if args.arm not in ("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast"):
        raise ValueError("fault trial requires a cascade arm")
    if args.v5 == "double" and not args.integration_double:
        raise ValueError("double fault trial must be marked integration-only")
    if args.out.exists() or args.work.exists():
        raise FileExistsError("new output and private work directories required")
    args.out.mkdir(parents=True)
    args.work.mkdir(parents=True)
    before_work, after_work = args.work / "before", args.work / "after"
    before_work.mkdir()
    after_work.mkdir()
    state = None
    try:
        state = launch(args, before_work, args.work / "before.stdout.txt")
        baseline = request(state, case)
        if not baseline["effect_observed"] or not baseline["app_received"]:
            raise RuntimeError("baseline control failed before fault injection")
        fault = inject(state, args.scenario)
        time.sleep(.3)
        impaired = request(state, case)
    finally:
        shutdown(before_work, args.out / "CLEAN.before.json")
    # Recovery here is an explicit pinned stack restart, not an autonomous heal claim.
    recovery_start = time.monotonic()
    try:
        restarted = launch(args, after_work, args.work / "after.stdout.txt")
        attempts = []
        for _ in range(10):
            probe = request(restarted, case)
            attempts.append(probe)
            if probe["effect_observed"] and probe["app_received"]:
                break
            time.sleep(.2)
        recovered = attempts[-1]["effect_observed"] is True and attempts[-1]["app_received"]
        recovery_s = time.monotonic() - recovery_start
    finally:
        shutdown(after_work, args.out / "CLEAN.after.json")
    result = {"schema": "challenge-fault-trial/v1",
              "scope": "INTEGRATION_DOUBLE" if args.integration_double else "REAL_V51_LAB",
              "app": args.app, "arm": args.arm, "scenario": args.scenario,
              "cases_sha256": trial.sha(args.cases), "seal_sha256": trial.sha(args.seal),
              "config_sha256": trial.sha(args.config), "apps_commit": state["apps_commit"],
              "baseline": baseline, "fault": fault, "impaired": impaired,
              "restart_recovered": recovered, "restart_recovery_s": recovery_s,
              "restart_requests_until_clean": len(attempts), "status": "COMPLETE"}
    (args.out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p.add_argument("--arm", choices=("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast"), required=True)
    p.add_argument("--scenario", choices=SCENARIOS, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--seal", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--v5", choices=("real", "double"), default="real")
    p.add_argument("--integration-double", action="store_true")
    p.add_argument("--handoff-gpu", action="store_true")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.handoff_gpu and args.v5 != "real":
            raise ValueError("GPU hand-off requires real V5.1")
        with temporary_handoff(args.handoff_gpu, args.work.parent / (args.work.name + ".gpu-lease")):
            result = run(args)
    except (OSError, ValueError, RuntimeError, FileExistsError, subprocess.CalledProcessError) as exc:
        p.exit(2, f"challenge-fault: {exc}\n")
    print(json.dumps({"out": str(args.out), "scenario": args.scenario,
                      "recovered": result["restart_recovered"]}, indent=2))


if __name__ == "__main__":
    main()
