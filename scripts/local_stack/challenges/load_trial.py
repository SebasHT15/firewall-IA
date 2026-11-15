"""Predeclared read-only offered-load run against one sealed challenge-app arm.

One run is one arm, rate, duration, concurrency and transport. Repeat in a
predeclared, alternating order. Results are operational measurements only;
repeated requests do not become independent quality labels.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(HERE), str(HERE.parent)]

import adapters  # noqa: E402
import smoke  # noqa: E402
import trial  # noqa: E402
from gpu_lease import temporary_handoff  # noqa: E402
from trial_client import TrialClient, TRANSPORTS  # noqa: E402


def shasum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sample_resources(state):
    sample = {"t_monotonic": time.monotonic(), "processes": {}, "containers": {},
              "gpu": None, "gpu_processes": None, "gateway_queues": None, "fast_path_audit": None}
    containers = []
    for component in state["components"]:
        if component["kind"] == "process":
            pid = component["pid"]
            try:
                status = Path(f"/proc/{pid}/status").read_text().splitlines()
                rss = next((int(x.split()[1]) for x in status if x.startswith("VmRSS:")), None)
                stat = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
                ticks = int(stat[11]) + int(stat[12])
                sample["processes"][component["name"]] = {"rss_kib": rss, "cpu_ticks": ticks}
            except (OSError, StopIteration, ValueError):
                sample["processes"][component["name"]] = {"rss_kib": None}
        elif component["kind"] == "container":
            containers.append((component["name"], component["container"]))
    if containers:
        proc = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}",
                               *(container for _, container in containers)],
                              capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            by_name = {}
            for line in proc.stdout.splitlines():
                try:
                    item = json.loads(line)
                    by_name[item.get("Name")] = item
                except ValueError:
                    continue
            for component_name, container in containers:
                item = by_name.get(container) or {}
                sample["containers"][component_name] = {
                    "cpu_percent": item.get("CPUPerc"), "mem_usage": item.get("MemUsage"),
                    "mem_percent": item.get("MemPerc")}
    proc = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,power.draw",
                           "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5)
    if proc.returncode == 0:
        sample["gpu"] = proc.stdout.strip().splitlines()
    proc = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                           "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5)
    if proc.returncode == 0:
        sample["gpu_processes"] = proc.stdout.strip().splitlines()
    admin = state.get("endpoints", {}).get("gateway_admin")
    if admin and state.get("firewall") == "cascade":
        try:
            with urlopen(admin + "/status", timeout=2) as response:
                status = json.load(response)
            sample["gateway_queues"] = status.get("queues")
            sample["fast_path_audit"] = status.get("fast_path_audit")
        except (OSError, ValueError):
            pass
    return sample



def admin_status(state):
    url = state.get('endpoints', {}).get('gateway_admin')
    if not url or state.get('firewall') != 'cascade':
        return None
    try:
        with urlopen(url+'/status',timeout=2) as response:
            return json.load(response)
    except (OSError,ValueError):
        return None

def run(args):
    cases = trial.validate_cases(args.cases, args.app)
    seal = json.loads(args.seal.read_text())
    if (seal.get("schema") != trial.SCHEMA or seal.get("status") != "SEALED" or
            seal.get("app") != args.app or seal.get("cases_sha256") != shasum(args.cases) or
            seal.get("metrics_spec_sha256") != shasum(trial.METRICS_SPEC) or
            seal.get("source_sha256") != trial.source_hashes()):
        raise ValueError("sealed case or measurement-spec identity mismatch")
    pinned = seal["configs"][args.arm]
    config = Path(pinned["path"])
    if shasum(config) != pinned["sha256"]:
        raise ValueError("stack config changed after seal")
    direct_rows = [json.loads(line) for line in Path(args.direct_rows).read_text().splitlines() if line.strip()]
    if shasum(args.direct_rows) != seal["direct_rows_sha256"]:
        raise ValueError("direct controls changed after seal")
    eligible = {r["case_id"] for r in direct_rows if r.get("effect_observed") is True}
    selected = [c for c in cases if c["case_id"] in args.case_id]
    if (len(selected) != len(args.case_id) or any(c["method"] not in ("GET", "HEAD") or
            c["label"] != "ALLOW" or c.get("effect_oracle") is None or
            c["case_id"] not in eligible for c in selected)):
        raise ValueError("load cases must be read-only benign controls with positive direct oracles")
    if args.arm == "direct" and args.transport == "h1_plain_gateway":
        raise ValueError("plain gateway transport has no direct arm")
    if args.v5 == "double" and not args.integration_double:
        raise ValueError("double is only for an explicitly marked integration run")
    if args.rps <= 0 or args.seconds <= 0 or args.workers < 1 or args.slo_ms <= 0:
        raise ValueError("rate, duration, workers and SLO must be positive")
    if args.warmup_requests < 0 or args.sample_seconds <= 0:
        raise ValueError("warmup count and resource sampling interval are invalid")
    if args.restart_front_at_seconds is not None and not 0 < args.restart_front_at_seconds < args.seconds:
        raise ValueError("front restart must be scheduled within the offered-load window")
    if args.out.exists() or args.work.exists():
        raise FileExistsError("new output and private work directories required")
    args.out.mkdir(parents=True)
    args.work.mkdir(parents=True)
    mapped, _fast = trial.config_arm(args.arm)
    command = [str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py")]
    clients = []
    clients_lock = threading.Lock()
    local = threading.local()
    samples = []
    stop = threading.Event()
    rows = []
    restart = {}
    start_wall = None
    try:
        with (args.work / "stack.stdout.txt").open("x") as output:
            t0 = time.monotonic()
            up = subprocess.run(command + ["up", "--app", args.app, "--arm", mapped,
                            "--config", str(config), "--work", str(args.work), "--v5", args.v5],
                            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=600)
            cold_start_s = time.monotonic() - t0
        if up.returncode:
            raise RuntimeError("stack startup failed; see private stack.stdout.txt")
        state = json.loads((args.work / "stack-state.json").read_text())
        if state.get("apps_commit") != adapters.PINNED_APPS_COMMIT or state.get("v5") != args.v5:
            raise RuntimeError("running application or V5 runtime identity drift")

        def worker(index, scheduled):
            if not hasattr(local, "client"):
                local.client = TrialClient(state, args.transport)
                with clients_lock:
                    clients.append(local.client)
            actual = time.monotonic()
            case = selected[index % len(selected)]
            response = local.client.request(case["method"], case["target"], case.get("headers", []),
                                            trial.body_bytes(case))
            finished = time.monotonic()
            okay = response.get("error") is None and trial.effect(case["effect_oracle"], response) is True
            return {"index": index, "case_id": case["case_id"], "scheduled_offset_s": scheduled - start_wall,
                    "finished_offset_s": finished - start_wall,
                    "client_queue_ms": (actual - scheduled) * 1000,
                    "end_to_end_ms": (finished - scheduled) * 1000,
                    "request_ms": response.get("elapsed_ms"), "status": response.get("status"),
                    "tcp_connect_ms": response.get("tcp_connect_ms"),
                    "tls_handshake_ms": response.get("tls_handshake_ms"),
                    "complete": response.get("error") is None, "useful": okay,
                    "response_bytes": len(response.get("body") or b""),
                    "alpn": response.get("alpn"), "tls_version": response.get("tls_version"),
                    "tls_session_reused": response.get("tls_session_reused"),
                    "connection_requests": response.get("connection_requests")}

        # Warmup is measured separately and excluded from offered-load denominators.
        warmup = []
        start_wall = time.monotonic()
        warm_client = TrialClient(state, args.transport)
        try:
            for i in range(args.warmup_requests):
                c = selected[i % len(selected)]
                t = time.monotonic()
                r = warm_client.request(c["method"], c["target"], c.get("headers", []), trial.body_bytes(c))
                warmup.append({"ms": (time.monotonic() - t) * 1000, "status": r.get("status"),
                               "useful": r.get("error") is None and trial.effect(c["effect_oracle"], r) is True})
        finally:
            warm_client.close()
        accounting_before_load = admin_status(state)
        decision_offset = (Path(state["gateway_decisions"]).stat().st_size
                           if state.get("gateway_decisions") else 0)

        def sampler():
            while not stop.is_set():
                try:
                    samples.append(sample_resources(state))
                except (OSError, subprocess.TimeoutExpired):
                    samples.append({"t_monotonic": time.monotonic(), "sample_error": True})
                stop.wait(args.sample_seconds)

        monitor = threading.Thread(target=sampler, daemon=True)
        monitor.start()
        count = math.ceil(args.rps * args.seconds)
        start_wall = time.monotonic()
        restart_thread = None
        if args.restart_front_at_seconds is not None:
            front_name = next(c["container"] for c in state["components"] if c["name"] == "front")
            def restart_front():
                delay = start_wall + args.restart_front_at_seconds - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                restart["started_offset_s"] = time.monotonic() - start_wall
                proc = subprocess.run(["docker", "restart", "-t", "1", front_name],
                                      capture_output=True, text=True, timeout=30)
                restart["ended_offset_s"] = time.monotonic() - start_wall
                restart["success"] = proc.returncode == 0
            restart_thread = threading.Thread(target=restart_front, daemon=True)
            restart_thread.start()
        futures = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for index in range(count):
                scheduled = start_wall + index / args.rps
                delay = scheduled - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                futures.append(pool.submit(worker, index, scheduled))
            for future in as_completed(futures):
                rows.append(future.result())
        finish_wall = time.monotonic()
        if restart_thread:
            restart_thread.join(timeout=35)
            if not restart.get("success"):
                raise RuntimeError("front restart under load did not complete")
        stop.set()
        monitor.join(timeout=10)
        rows.sort(key=lambda r: r["index"])
        if restart:
            post = [r for r in rows if r["finished_offset_s"] >= restart["ended_offset_s"]]
            streak = 0
            for index, row in enumerate(post, 1):
                streak = streak + 1 if row["useful"] and row["end_to_end_ms"] <= args.slo_ms else 0
                if streak >= 5:
                    restart["recovery_s_after_restart_end"] = (
                        row["finished_offset_s"] - restart["ended_offset_s"])
                    restart["requests_until_five_clean"] = index
                    break
            restart.setdefault("recovery_s_after_restart_end", None)
            restart.setdefault("requests_until_five_clean", None)
        with (args.out / "ROWS.jsonl").open("x") as output:
            for row in rows:
                output.write(json.dumps(row, sort_keys=True) + "\n")
        (args.out / "RESOURCES.jsonl").write_text("".join(json.dumps(s, sort_keys=True) + "\n"
                                                       for s in samples))
        decision_rows, _ = smoke.new_json_lines(state.get("gateway_decisions"), decision_offset)
        decisions = [r for r in decision_rows if r.get("kind") == "decision"]
        def values(path):
            out = []
            for d in decisions:
                v = d
                for key in path:
                    v = v.get(key) if isinstance(v, dict) else None
                if isinstance(v, (int, float)):
                    out.append(v)
            return out
        def pct(nums):
            return {"n": len(nums), "p50": trial_percentile(nums, .5),
                    "p95": trial_percentile(nums, .95), "p99": trial_percentile(nums, .99)}
        summary = {"schema": "challenge-load-trial/v1",
                   "scope": "INTEGRATION_DOUBLE" if args.integration_double else "SEALED_REAL_OPERATIONAL",
                   "app": args.app, "arm": args.arm, "v5": args.v5,
                   "transport": args.transport, "cases_sha256": shasum(args.cases),
                   "seal_sha256": shasum(args.seal), "config_sha256": shasum(config),
                   "selected_case_ids": args.case_id, "apps_commit": state["apps_commit"],
                   "rps_offered_target": args.rps, "seconds_target": args.seconds,
                   "workers": args.workers, "slo_ms": args.slo_ms,
                   "warmup": warmup, "cold_start_s": cold_start_s,
                   "front_restart_under_load": restart or None,
                   "offered": count, "completed": sum(r["complete"] for r in rows),
                   "useful": sum(r["useful"] for r in rows),
                   "useful_under_slo": sum(r["useful"] and r["end_to_end_ms"] <= args.slo_ms
                                           for r in rows),
                   "elapsed_until_last_response_s": finish_wall - start_wall,
                   # Rate denominators are explicit. The useful/completed windows include the
                   # whole declared offer duration plus any post-offer drain, so early-finishing
                   # runs can never report a useful rate above the offered rate (reviewer finding
                   # 2026-11-07). The offered rate is over the declared offer window only.
                   "offered_window_s": args.seconds,
                   "observed_window_s": max(args.seconds, finish_wall - start_wall),
                   "rates": {
                       "denominator_offered": "seconds_target (declared offer window)",
                       "denominator_served": ("observed_window_s = "
                                              "max(seconds_target, elapsed_until_last_response_s)"),
                       "offered_rps": count / args.seconds,
                       "completed_rps": (sum(r["complete"] for r in rows)
                                         / max(args.seconds, finish_wall - start_wall)),
                       "useful_rps": (sum(r["useful"] for r in rows)
                                      / max(args.seconds, finish_wall - start_wall)),
                       "useful_under_slo_rps": (
                           sum(r["useful"] and r["end_to_end_ms"] <= args.slo_ms for r in rows)
                           / max(args.seconds, finish_wall - start_wall)),
                   },
                   "useful_rps": (sum(r["useful"] for r in rows)
                                  / max(args.seconds, finish_wall - start_wall)),
                   "status_counts": dict(Counter(str(r["status"]) for r in rows)),
                   "latency_ms": pct([r["end_to_end_ms"] for r in rows]),
                   "client_queue_ms": pct([r["client_queue_ms"] for r in rows]),
                   "tls_handshake_ms": pct([r["tls_handshake_ms"] for r in rows
                                              if isinstance(r.get("tls_handshake_ms"), (int, float))]),
                   "gateway_status_before_load": accounting_before_load,
                   "gateway_status_after_load": admin_status(state),
                   "gateway_decisions": len(decisions),
                   "fast_path_hits": sum(d.get("deciding_stage") == "fast_path" and d.get("applied") == "FORWARD" for d in decisions),
                   "foreground_v5_calls": sum(d.get("v5") is not None for d in decisions),
                   "foreground_v5_stage_ms_sum": sum(float((d.get("stage_ms") or {}).get("v5") or 0) for d in decisions),
                   "unexpected_model2_records": sum(d.get("model2") is not None for d in decisions),
                   "gateway_stage_ms": {name: pct(values(("stage_ms", name))) for name in
                                        ("admission", "canonical", "fast_path", "request_guard", "model2", "v5")},
                   "v5_queue_wait_ms": pct(values(("v5_service", "queue_wait_ms"))),
                   "resource_samples": len(samples), "rows_sha256": shasum(args.out / "ROWS.jsonl"),
                   "resources_sha256": shasum(args.out / "RESOURCES.jsonl"),
                   "status": "COMPLETE_PENDING_CLEAN"}
        (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    finally:
        stop.set()
        for client in clients:
            client.close()
        if (args.work / "stack-state.json").exists():
            subprocess.run(command + ["down", "--work", str(args.work)], cwd=ROOT,
                           capture_output=True, text=True)
            clean = subprocess.run(command + ["check-clean", "--work", str(args.work)], cwd=ROOT,
                                   capture_output=True, text=True)
            (args.out / "CLEAN.json").write_text(clean.stdout)
            if clean.returncode:
                raise RuntimeError("load trial left stack resources")
    summary["gateway_shutdown_accounting"] = trial.shutdown_accounting(state)
    summary["status"] = "COMPLETE"
    (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def trial_percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    low, high = int(pos), min(len(values) - 1, int(pos) + 1)
    return values[low] + (values[high] - values[low]) * (pos - low)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p.add_argument("--arm", choices=trial.ARMS, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--case-id", action="append", required=True)
    p.add_argument("--direct-rows", type=Path, required=True)
    p.add_argument("--seal", type=Path, required=True)
    p.add_argument("--transport", choices=TRANSPORTS, required=True)
    p.add_argument("--rps", type=float, required=True)
    p.add_argument("--seconds", type=float, required=True)
    p.add_argument("--workers", type=int, required=True)
    p.add_argument("--slo-ms", type=float, required=True)
    p.add_argument("--warmup-requests", type=int, default=2)
    p.add_argument("--sample-seconds", type=float, default=1.0)
    p.add_argument("--restart-front-at-seconds", type=float,
                   help="inject one recorded front-container restart during offered load")
    p.add_argument("--v5", choices=("real", "double"), default="real")
    p.add_argument("--integration-double", action="store_true")
    p.add_argument("--handoff-gpu", action="store_true")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.handoff_gpu and (args.arm not in ("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast") or args.v5 != "real"):
            raise ValueError("GPU hand-off applies only to a real V5.1 arm")
        with temporary_handoff(args.handoff_gpu, args.work.parent / (args.work.name + ".gpu-lease")):
            result = run(args)
    except (OSError, ValueError, RuntimeError, FileExistsError) as exc:
        p.exit(2, f"challenge-load: {exc}\n")
    print(json.dumps({"out": str(args.out), "status": result["status"], "offered": result["offered"],
                      "useful": result["useful"]}, indent=2))


if __name__ == "__main__":
    main()
