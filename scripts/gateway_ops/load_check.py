"""
Sustained load, saturation and recovery of the cascade gateway with real services.

    .venv-dataplane/bin/python scripts/gateway_ops/load_check.py --out <evidence dir> --work <private dir> \
        --manifest <manifest.json> --inputs <private inputs.jsonl> --phase ladder

Phases: ladder (saturation search and recovery), soak, audit (Fast Path), failures.

For a delivered candidate use `--candidate-manifest` (`run_candidate_load.sh`): the configuration under
test is then `candidate`, V4 is not needed unless `--with-v4` is given, and every identity comes from
that v2 manifest. Rates that depend on where a candidate saturates are arguments, never constants.

Experimental scope: HTTP/1.1 cleartext reverse proxy on loopback, to an inert sink. A rate measured
here is what this machine did with this DEV mix. It is not a capacity of any deployment, and the sink
only proves delivery.

THE EXPERIMENT. Open-loop Poisson arrivals over the whole authorized DEV population (`load_lib`). The
same seeded order and the same arrival seeds are used by every mode inside one repetition, and modes
run in a balanced order. Every run uses fresh service processes and only the services its mode needs,
and starts with a warm-up that is recorded apart. The order of the cases, the arrival seeds, every
limit and the saturation criteria are written to `protocol.json` before anything runs.

The operating limits are those of `config.cascade.example.yaml`, written before any of this was
measured and not tuned from it. No threshold is selected and no protected set is read.

PRIVACY. `--work` receives logs that can hold request paths and must stay out of the repository.
`--out` receives only ids, closed codes and numbers.

A run writes its result when it ends and a finished run is skipped, so the program can be restarted.
Finding a compute process it did not start stops the program: that run would no longer be isolated.
Without `--doubles` it refuses to start unless `GPU_STATUS.json` shows the GPU was handed over.
"""
import argparse
import asyncio
import collections
import hashlib
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import cascade_manifest as CM  # noqa: E402
import fast_path as fp        # noqa: E402
import gpu_gate               # noqa: E402
import live_check as LC       # noqa: E402
import live_stack as L        # noqa: E402
import load_lib as LL         # noqa: E402

LEVELS = (1, 2, 3, 4, 6, 8, 12, 16, 24)
# (V5 configuration, mode). `reference` is the configuration served by default. `verified` is the
# experimental verified-suffix candidate, kept separate. V4_ONLY loads no V5.
RUNS = (("v4", "V4_ONLY"), ("reference", "V5_ONLY"), ("verified", "V5_ONLY"),
        ("reference", "CASCADE_ACTIVE"), ("verified", "CASCADE_ACTIVE"),
        ("reference", "CASCADE_OBSERVE"), ("verified", "CASCADE_OBSERVE"))
SEED = 20261031
STEP_SECONDS = 30
PROBE_RATE = 1.0
PROBE_SECONDS = 45
OVERLOAD_SECONDS = 45
SOAK_SECONDS = 240
SOAK_REPETITIONS = 2
SOAK_HIGH_MODES = ("V5_ONLY", "CASCADE_ACTIVE")
RECOVERY_RUNS = (("v4", "V4_ONLY"), ("reference", "CASCADE_OBSERVE"), ("verified", "CASCADE_OBSERVE"))
CANDIDATE_RUNS = (("candidate", "V5_ONLY"), ("candidate", "CASCADE_ACTIVE"))
CANDIDATE_V4_RUNS = (("v4", "V4_ONLY"), ("candidate", "CASCADE_OBSERVE"))
RECOVERY_REPETITIONS = 2
RECOVERY_RATE = 9.0           # 1.5 x the rate at which V4 saturated
RECOVERY_LOAD_SECONDS = 90
RECOVERY_MAX_SECONDS = 420
PROBE_BATCH = 15
RETURN_RATE = 8.0
RETURN_PAUSE = 50.0
RETURN_REPETITIONS = 2
WARMUP_REQUESTS = 20
CLIENT_TIMEOUT = 15.0
AUDIT_RATES = (0.0, 0.1, 1.0)
AUDIT_SECONDS = 90
AUDIT_REPETITIONS = 2
AUDIT_DEV_RATE = 1.5
AUDIT_PERMIT_RATE = 5.0
# `unbounded` is how the audit ran before it had a budget, kept as the comparison. `bounded` holds the
# values of config.cascade.example.yaml. Neither is a selected operating value.
AUDIT_BUDGETS = {"unbounded": dict(audit_per_second=1e6, audit_burst=1000000,
                                   audit_yield_inflight=1000000, audit_max_age=3600.0),
                 "bounded": dict(audit_per_second=2.0, audit_burst=4, audit_yield_inflight=1,
                                 audit_max_age=2.0)}
FAILURE_RATE = 2.0
FAILURE_REPETITIONS = {"verified": 2, "reference": 1}
# As in config.cascade.example.yaml, except where a value only describes this harness.
OPERATING = dict(v4_timeout=3.0, v5_timeout=3.0, deadline=5.0, max_inflight=8, max_waiting=16,
                 worker_backoff=2.0, probe_interval=2.0, observe_max_pending=16,
                 audit_queue_size=64, audit_timeout=5.0)
FAULT_FILE = "GUARD_FAULT"
GUARD_FIXTURE = os.path.join(HERE, "fixtures", "guard_fault_addon.py")
SERVICE_ENV = dict(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONDONTWRITEBYTECODE="1",
                   TOKENIZERS_PARALLELISM="false")
CLOCK_TICK = os.sysconf("SC_CLK_TCK")


class ForeignGpuProcess(RuntimeError):
    pass


def proc_table():
    """pid -> (ppid, cpu ticks, rss KiB, command line) for every readable process."""
    table = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="latin-1") as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                command = fh.read()
            table[int(entry)] = (int(fields[1]), int(fields[11]) + int(fields[12]),
                                 int(fields[21]) * os.sysconf("SC_PAGE_SIZE") // 1024, command)
        except (OSError, IndexError, ValueError):
            continue
    return table


class Sampler(threading.Thread):
    """Resources once a second, per role, plus the GPU and any compute process that is not ours."""

    def __init__(self, deployment):
        super().__init__(daemon=True)
        self.deployment = deployment
        self.samples = []
        self.foreign = set()
        self.stop_event = threading.Event()

    def roles(self, table):
        out = {}
        for role, proc in self.deployment.services.items():
            if proc.poll() is None:
                out[role] = [proc.pid]
        gateway = self.deployment.stack.gateway_proc
        if gateway is not None and gateway.poll() is None:
            out["gateway"] = [gateway.pid]
            workers = collections.defaultdict(list)
            for pid, row in table.items():
                if row[0] == gateway.pid:
                    name = "model2_worker" if b"model2_worker" in row[3] else "canonical_workers"
                    workers[name].append(pid)
            out.update(workers)
        return out

    def run(self):
        while not self.stop_event.is_set():
            table = proc_table()
            sample = {"t": time.time(), "roles": {}}
            for role, pids in self.roles(table).items():
                rows = [table[p] for p in pids if p in table]
                sample["roles"][role] = {"ticks": sum(r[1] for r in rows),
                                         "rss_kib": sum(r[2] for r in rows)}
            status = self.deployment.stack.status() if self.deployment.mode != "V4_ONLY" else None
            if status is not None and status.get("queues"):
                sample["queues"] = status["queues"]
            if not self.deployment.args.doubles:   # a dry run uses no GPU, so it has nothing to guard
                sample["gpu"] = subprocess.run(
                    ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,temperature.gpu,power.draw,clocks.sm",
                     "--format=csv,noheader,nounits"], capture_output=True, text=True).stdout.strip()
                apps = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name",
                                       "--format=csv,noheader"], capture_output=True, text=True).stdout
                for line in apps.splitlines():
                    pid = line.split(",")[0].strip()
                    if pid.isdigit() and "ptyxis" not in line \
                            and int(pid) not in self.deployment.known_pids:
                        self.foreign.add(line.strip())
            self.samples.append(sample)
            self.stop_event.wait(1.0)

    def window(self, t0, t1):
        rows = [s for s in self.samples if t0 <= s["t"] <= t1]
        out = {"samples": len(rows), "roles": {}}
        roles = {r for s in rows for r in s["roles"]}
        for role in sorted(roles):
            series = [(s["t"], s["roles"][role]) for s in rows if role in s["roles"]]
            cpu = [(b["ticks"] - a["ticks"]) / CLOCK_TICK / (tb - ta) * 100
                   for (ta, a), (tb, b) in zip(series, series[1:])
                   if tb > ta and b["ticks"] >= a["ticks"]]
            out["roles"][role] = {
                "cpu_percent_mean": sum(cpu) / len(cpu) if cpu else None,
                "cpu_percent_max": max(cpu) if cpu else None,
                "rss_mib_first": series[0][1]["rss_kib"] / 1024,
                "rss_mib_max": max(r["rss_kib"] for _, r in series) / 1024}
        depths = collections.defaultdict(list)
        for s in rows:
            for name, value in (s.get("queues") or {}).items():
                if value is not None:
                    depths[name].append(value)
        out["queues"] = {name: {"mean": sum(v) / len(v), "max": max(v), "samples": len(v)}
                         for name, v in sorted(depths.items())}
        gpu = []
        for s in rows:
            try:
                gpu.append([float(x) for x in s.get("gpu", "").split(",")])
            except ValueError:
                continue
        if gpu:
            out["gpu"] = {"util_mean": sum(g[0] for g in gpu) / len(gpu), "util_max": max(g[0] for g in gpu),
                          "memory_mib_max": max(g[1] for g in gpu), "temp_c_max": max(g[2] for g in gpu),
                          "power_w_mean": sum(g[3] for g in gpu) / len(gpu),
                          "clock_mhz_min": min(g[4] for g in gpu)}
        return out


class Deployment:
    """Fresh services and gateway for one run. Terminates only what it started."""

    def __init__(self, args, name, mode, config, *, v4=False, v5=False, fast_path=False,
                 overrides=None, extra=()):
        self.args, self.name, self.mode, self.config = args, name, mode, config
        self.workdir = os.path.join(args.work, name)
        # A run that did not finish left no result: start it clean rather than mix its data.
        shutil.rmtree(self.workdir, ignore_errors=True)
        os.makedirs(self.workdir)
        rows = os.path.join(args.out, "rows", f"{name}.jsonl")
        if os.path.exists(rows):
            os.unlink(rows)
        self.known_pids = set()
        self.want = {"v4": v4, "v5": v5}
        self.ports = {"v4": L.free_port(), "v5": L.free_port()}
        self.urls = {role: f"http://127.0.0.1:{port}" for role, port in self.ports.items()}
        limits = dict(OPERATING, **(overrides or {}))
        if fast_path:
            limits.update(fast_path_policy=LC.POLICY, fast_path_sha256=fp.load_policy(LC.POLICY).sha256)
        self.stack = L.Stack(self.workdir, mode=mode, manifest=args.manifests[config],
                             v5_url=self.urls["v5"], v4_url=self.urls["v4"], config_overrides=limits,
                             mitmdump_extra=extra)
        self.services = {}
        self.tails = {}
        self.sampler = None
        self.steps = []
        self.metrics_before = {}

    def start_service(self, role):
        log_path = os.path.join(self.workdir, f"{role}.log")
        log = open(log_path, "ab")
        if self.args.doubles:
            argv = [L.PYTHON, os.path.join(HERE, "service_doubles.py"), "--role", role, "--port",
                    str(self.ports[role]), "--manifest", self.args.manifests[self.config]]
        else:
            app = "classifier_api:app" if role == "v4" else "v5_classifier_api:app"
            argv = ["/usr/bin/python3.12", "-B", "-m", "uvicorn", "--app-dir",
                    os.path.join(REPO, "control_plane"), app, "--host", "127.0.0.1", "--port",
                    str(self.ports[role])]
        env = {k: v for k, v in os.environ.items() if not k.startswith("FIREWALL_V5_")}
        env.update(SERVICE_ENV)
        if role == "v5":
            env.update(self.args.service_env.get(self.config, {}))
        self.services[role] = subprocess.Popen(argv, cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
                                               env=env, start_new_session=True)
        self.known_pids.add(self.services[role].pid)
        log.close()

    def wait_service(self, role, timeout=90.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, body = L.http_get(self.urls[role] + "/health", timeout=1.0)
            if status == 200 and json.loads(body).get("model_loaded"):
                return json.loads(body)
            if self.services[role].poll() is not None:
                raise RuntimeError(f"{role} service exited")
            time.sleep(0.1)
        raise TimeoutError(f"{role} service did not load")

    def __enter__(self):
        try:
            self.health = {}
            for role in ("v4", "v5"):
                if self.want[role]:
                    self.start_service(role)
            for role in ("v4", "v5"):
                if self.want[role]:
                    self.health[role] = self.wait_service(role)
            self.stack.start()
            if self.mode == "V4_ONLY":
                time.sleep(1.0)
            else:
                self.stack.wait_ready(timeout=60.0, require_cascade=self.want["v5"])
            if self.args.doubles and self.want["v5"]:
                self.stack.control("v5", self.args.double_behavior,
                                   inference_ms=self.args.double_inference_ms)
        except BaseException:
            self.close()
            raise
        for name, path in (("decisions", "decisions.jsonl"), ("sink", "sink.jsonl"),
                           ("gateway", "gateway.log"), ("v4", "v4.log"), ("v5", "v5.log")):
            self.tails[name] = LL.LogTail(os.path.join(self.workdir, path))
        self.sampler = Sampler(self)
        self.sampler.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.sampler is not None:
            self.sampler.stop_event.set()
            self.sampler.join(5)
        self.stack.stop()
        for proc in self.services.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def metrics(self):
        status, body = self.stack.admin("/metrics")
        return LL.parse_metrics(body.decode("utf-8")) if status == 200 else {}

    def settle(self):
        """Until the records stop growing: observations and audits finish after the responses."""
        path = os.path.join(self.workdir, "decisions.jsonl")
        last, quiet = -1, time.monotonic()
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            size = os.path.getsize(path) if os.path.exists(path) else 0
            if size != last:
                last, quiet = size, time.monotonic()
            elif time.monotonic() - quiet > 1.5:
                return
            time.sleep(0.1)

    def json_tail(self, name):
        return [json.loads(line) for line in self.tails[name].read()]

    def collect(self, label, rate, seconds, rows, t0, t1, l2_rows=None, faults_expected=False,
                **extra):
        """`l2_rows`: every request whose reception falls in this window, when that is more than the
        ones being accounted (an overload step and the probes that overlap its tail).
        `faults_expected`: a failure timeline has decisions that cannot arrive (sink down) and arrivals
        with no decision record (V4 during a return), so that comparison does not apply. The client
        against reception one still does."""
        self.settle()
        records = self.json_tail("decisions")
        sink_rows = self.json_tail("sink")
        v4_lines, v5_lines = self.tails["v4"].read(), self.tails["v5"].read()
        v5_counts = LL.v5_service_counts(v5_lines)
        after = self.metrics()
        accounting = LL.client_accounting(rows, seconds)
        l2 = LL.l2_multiset(rows if l2_rows is None else l2_rows, sink_rows)
        decided = collections.Counter(r["wire_sha256"] for r in records
                                      if r.get("kind") == "decision" and r.get("applied") == "FORWARD"
                                      and r.get("wire_sha256"))
        if decided and not faults_expected:
            l2["decided_forward_equals_received"] = decided == collections.Counter(
                r["wire_sha256"] for r in sink_rows)
        step = {
            "label": label, "offered_rate": rate, "seconds": seconds, "t0": t0, "t1": t1,
            "client": accounting, "saturated": LL.is_saturated(accounting), "L2": l2,
            "decisions": LL.decision_accounting(records),
            "observations": dict(collections.Counter(
                r["observation"] for r in records if r.get("observation"))),
            "cascade_vs_applied": dict(collections.Counter(
                "same" if r.get("applied") == r.get("cascade_applied") else "different"
                for r in records if r.get("observation") == "computed")),
            "audit": dict(collections.Counter(
                f"{r['status']}:{r.get('verdict')}" for r in records
                if r.get("kind") == "fast_path_audit")),
            "audit_accounting": (self.stack.status() or {}).get("fast_path_audit"),
            "egress": dict(collections.Counter(
                f"{r['event']}:{(r.get('reason') or 'none').split(':')[0]}" for r in records
                if r.get("kind") == "egress")),
            "v4_gateway_ms": LL.dist(LL.gateway_v4_ms(self.tails["gateway"].read())),
            "v4_model_ms": LL.dist(LL.v4_model_ms(v4_lines)),
            "v5_generate_service_ms": LL.dist(v5_counts["generate_ms"]),
            "v5_service": {k: v for k, v in v5_counts.items() if k != "generate_ms"},
            "gateway_metric_delta": LL.metric_delta(self.metrics_before, after),
            "resources": self.sampler.window(t0, time.time()),
            **extra}
        self.metrics_before = after
        self.steps.append(step)
        self.write_rows(label, rows)
        print(f"  {self.name} {label}: offered {accounting['offered_per_s']:.2f}/s useful "
              f"{accounting['useful_per_s']:.2f}/s 503={accounting['rejected_503']} "
              f"timeouts={accounting['client_timeouts']} p95={accounting['latency_useful_ms'].get('p95')} "
              f"saturated={step['saturated']} L2={l2['conformant']}", flush=True)
        if self.sampler.foreign:
            raise ForeignGpuProcess(sorted(self.sampler.foreign))
        return step

    def write_rows(self, label, rows):
        path = os.path.join(self.args.out, "rows", f"{self.name}.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            for row in rows:
                safe = {k: v for k, v in row.items() if k != "wire_sha256"}
                fh.write(json.dumps({"step": label, **safe}, sort_keys=True) + "\n")

    def warmup(self, order):
        """Recorded apart and left out of every step."""
        cases = order.take(self.args.warmup_requests)
        t0 = time.time()
        rows = asyncio.run(LL.open_loop("127.0.0.1", self.stack.listen_port, cases,
                                        [i * 1.0 for i in range(len(cases))], CLIENT_TIMEOUT))
        return self.collect("warmup", 1.0, float(len(cases)), rows, t0, time.time())

    def step(self, order, label, rate, seconds, seed):
        offsets = LL.poisson_offsets(rate, seconds, seed)
        cases = order.take(len(offsets))
        t0 = time.time()
        rows = asyncio.run(LL.open_loop("127.0.0.1", self.stack.listen_port, cases, offsets,
                                        CLIENT_TIMEOUT))
        return self.collect(label, rate, seconds, rows, t0, time.time())

    def save(self, **fields):
        document = {"name": self.name, "mode": self.mode, "health": {
            role: {k: v for k, v in h.items() if k not in ("adapter_dir",)}
            for role, h in self.health.items()}, "steps": self.steps, **fields}
        with open(os.path.join(self.args.out, f"{self.name}.json"), "x", encoding="utf-8") as fh:
            json.dump(document, fh, indent=1, sort_keys=True)
            fh.write("\n")
        config = os.path.join(self.workdir, "gateway.yaml")
        if os.path.exists(config):
            with open(config, "rb") as src, open(
                    os.path.join(self.args.out, "configs", f"{self.name}.gateway.json"), "wb") as dst:
                dst.write(src.read())


def needs(mode):
    return dict(v4=mode in ("V4_ONLY", "CASCADE_OBSERVE"), v5=mode != "V4_ONLY")


def done(args, name):
    return os.path.exists(os.path.join(args.out, f"{name}.json"))


def run_overload_and_probe(deployment, order, rate, limit_ms, seed):
    """Overload, then drop at once to a light probe while the tail is still draining. Recovery is the
    time until probes are clean again; a fast refusal does not count as recovered."""
    args = deployment.args

    async def scenario():
        offsets = LL.poisson_offsets(rate, args.overload_seconds, seed)
        cases = order.take(len(offsets))
        port = deployment.stack.listen_port
        tasks = await LL.launch("127.0.0.1", port, cases, offsets, CLIENT_TIMEOUT)
        await asyncio.sleep(max(0.0, args.overload_seconds - offsets[-1]))
        load_end = time.time()
        probe_offsets = [i / PROBE_RATE for i in range(int(args.probe_seconds * PROBE_RATE))]
        probes = await LL.open_loop("127.0.0.1", port, order.take(len(probe_offsets)), probe_offsets,
                                    CLIENT_TIMEOUT, kind="probe")
        return await asyncio.gather(*tasks), probes, load_end

    t0 = time.time()
    rows, probes, load_end = asyncio.run(scenario())
    deployment.collect("overload", rate, args.overload_seconds, rows, t0, load_end,
                       l2_rows=rows + probes,
                       probe_client=LL.client_accounting(probes, args.probe_seconds),
                       recovery_limit_ms=limit_ms)
    deployment.write_rows("probe", probes)
    return LL.recovery_seconds(probes, load_end, limit_ms), load_end


def ladder(args, config, mode, rep):
    name = f"ladder_{config}_{mode}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + rep)
    with Deployment(args, name, mode, config, **needs(mode)) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        streak, first_saturated, last_good, baseline = 0, None, None, None
        for index, rate in enumerate(args.levels):
            step = deployment.step(order, f"rate_{rate}", rate, args.step_seconds, SEED + rep * 100 + index)
            if baseline is None:
                baseline = step["client"]["latency_useful_ms"].get("p95")
            if step["saturated"]:
                streak += 1
                first_saturated = first_saturated or rate
            else:
                streak, first_saturated, last_good = 0, None, rate
            if streak == 2:
                break
        overload_rate = 1.5 * (first_saturated or args.levels[-1])
        limit_ms = 2 * (baseline or 1000.0)
        recovery, load_end = run_overload_and_probe(deployment, order, overload_rate, limit_ms,
                                                    SEED + rep * 100 + 50)
        deployment.save(rep=rep, order_sha256=order.sha256, max_sustainable_rate=last_good,
                        first_saturated_rate=first_saturated, overload_rate=overload_rate,
                        recovery_limit_ms=limit_ms, recovery_seconds=recovery, load_end=load_end,
                        recovered=recovery is not None)
        print(f"  {name}: sustainable={last_good} saturated_at={first_saturated} recovery={recovery}",
              flush=True)


def soak(args, family, config, mode, rep, rate, prefix="soak"):
    name = f"{prefix}_{family}_{mode}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name} at {rate}/s", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 10 + rep)
    with Deployment(args, name, mode, config, **needs(mode)) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        step = deployment.step(order, "soak", rate, args.soak_seconds, SEED + 1000 + rep)
        deployment.save(rep=rep, order_sha256=order.sha256, soak_rate=rate,
                        drift=drift(deployment, step))


def drift(deployment, step):
    """Latency and memory at the start and the end of the soak: does anything accumulate?"""
    path = os.path.join(deployment.args.out, "rows", f"{deployment.name}.jsonl")
    with open(path, encoding="utf-8") as fh:
        rows = [r for r in map(json.loads, fh) if r["step"] == "soak"]
    rows.sort(key=lambda r: r["t_sched"])
    third = len(rows) // 3
    first, last = rows[:third], rows[-third:]
    return {"first_third_useful_ms": LL.dist([r["latency_ms"] for r in first if LL.useful(r)]),
            "last_third_useful_ms": LL.dist([r["latency_ms"] for r in last if LL.useful(r)]),
            "first_third_503": sum(r["status"] == 503 for r in first),
            "last_third_503": sum(r["status"] == 503 for r in last),
            "rss_mib": {role: (v["rss_mib_first"], v["rss_mib_max"])
                        for role, v in step["resources"]["roles"].items()}}


def permit_cases():
    """Synthetic requests the experimental Fast Path fixture matches. Not DEV traffic."""
    out = []
    for i in range(200):
        wire = LC.HEALTHZ if i % 2 == 0 else \
            b"GET /status?page=%d HTTP/1.1\r\nHost: lab.local\r\n\r\n" % (i % 1000)
        out.append({"id": f"fixture-permit-{i}", "wire_bytes": wire,
                    "wire_sha256": hashlib.sha256(wire).hexdigest()})
    return out


def audit_cell(args, config, sample_rate, rep, budget="unbounded"):
    suffix = "" if budget == "unbounded" else f"_{budget}"
    name = f"audit_{config}_rate{sample_rate}{suffix}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 20 + rep)
    with Deployment(args, name, "CASCADE_ACTIVE", config, v5=True, fast_path=True,
                    overrides={"sample_rate": sample_rate, **AUDIT_BUDGETS[budget]}) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        dev_offsets = LL.poisson_offsets(args.audit_dev_rate, args.audit_seconds, SEED + 2000 + rep)
        permit_offsets = LL.poisson_offsets(args.audit_permit_rate, args.audit_seconds, SEED + 2100 + rep)
        dev_cases = order.take(len(dev_offsets))
        permits = (permit_cases() * (1 + len(permit_offsets) // 200))[:len(permit_offsets)]

        async def scenario():
            port = deployment.stack.listen_port
            return await asyncio.gather(
                LL.open_loop("127.0.0.1", port, dev_cases, dev_offsets, CLIENT_TIMEOUT, kind="dev"),
                LL.open_loop("127.0.0.1", port, permits, permit_offsets, CLIENT_TIMEOUT, kind="permit"))

        t0 = time.time()
        dev, permit = asyncio.run(scenario())
        deployment.collect(
            "audit", args.audit_dev_rate + args.audit_permit_rate, args.audit_seconds, dev + permit, t0,
            time.time(), sample_rate=sample_rate,
            dev_client=LL.client_accounting(dev, args.audit_seconds),
            permit_client=LL.client_accounting(permit, args.audit_seconds))
        deployment.save(rep=rep, sample_rate=sample_rate, audit_budget=budget, order_sha256=order.sha256)


class LoadThread(threading.Thread):
    """Constant open-loop load for a whole failure timeline."""

    def __init__(self, deployment, cases, offsets):
        super().__init__(daemon=True)
        self.deployment, self.cases, self.offsets = deployment, cases, offsets
        self.rows = []

    def run(self):
        self.rows = asyncio.run(LL.open_loop("127.0.0.1", self.deployment.stack.listen_port, self.cases,
                                             self.offsets, CLIENT_TIMEOUT))


def worker_pids(deployment, needle):
    return [pid for pid, row in proc_table().items()
            if row[0] == deployment.stack.gateway_proc.pid and needle in row[3]]


def wait_ready(deployment):
    return deployment.stack.wait_ready(timeout=60.0, require_cascade=True)


def failure_timeline(args, deployment, mark):
    """Each fault against the running system, with the load never stopping."""
    pause = args.failure_pause
    stack = deployment.stack

    mark("baseline")
    time.sleep(pause * 2)

    mark("v5_killed")
    os.kill(deployment.services["v5"].pid, signal.SIGKILL)
    deployment.services["v5"].wait()
    time.sleep(pause)
    mark("v5_restarting")
    deployment.start_service("v5")
    deployment.wait_service("v5")
    wait_ready(deployment)
    mark("v5_recovered")
    time.sleep(pause)

    mark("model2_killed")
    for pid in worker_pids(deployment, b"model2_worker"):
        os.kill(pid, signal.SIGKILL)
    time.sleep(pause)

    mark("model2_hung")
    for pid in worker_pids(deployment, b"model2_worker"):
        os.kill(pid, signal.SIGSTOP)
    time.sleep(pause)

    mark("canonical_killed")
    for pid in worker_pids(deployment, b"cascade_canonical_worker"):
        os.kill(pid, signal.SIGKILL)
    time.sleep(pause)

    mark("v5_hung")
    os.kill(deployment.services["v5"].pid, signal.SIGSTOP)
    time.sleep(pause)
    mark("v5_resumed")
    os.kill(deployment.services["v5"].pid, signal.SIGCONT)
    wait_ready(deployment)
    mark("v5_resumed_ready")
    time.sleep(pause)

    mark("guard_stopped")
    open(os.environ["FIREWALL_GUARD_FAULT_FILE"], "w").close()
    time.sleep(pause)
    wait_ready(deployment)
    mark("guard_recovered")
    time.sleep(pause)

    mark("sink_killed")
    sink = next(p for p in reversed(stack.procs) if "independent_sink" in " ".join(p.args))
    sink.kill()
    sink.wait()
    time.sleep(pause)
    mark("sink_restarted")
    stack.restart_sink()
    time.sleep(pause)

    if args.with_v4:
        mark("v5_killed_before_return")
        os.kill(deployment.services["v5"].pid, signal.SIGKILL)
        deployment.services["v5"].wait()
        time.sleep(pause / 2)
        mark("return_to_v4")
        stack.rollback(True)
        time.sleep(pause)
        mark("v5_back_during_return")
        deployment.start_service("v5")
        deployment.wait_service("v5")
        time.sleep(pause / 2)
        mark("authority_back")
        stack.rollback(False)
        wait_ready(deployment)
        mark("authority_back_ready")
        time.sleep(pause)

    mark("gateway_killed")
    stack.gateway_proc.kill()
    stack.gateway_proc.wait()
    time.sleep(pause / 2)
    mark("gateway_restarting")
    stack.start_gateway()
    stack.wait_port(stack.listen_port)
    wait_ready(deployment)
    mark("gateway_ready")
    time.sleep(pause)
    mark("end")


FAILURE_SECONDS = 300


def phases(rows, events):
    """Accounting per timeline phase. A row belongs to the phase in which it was scheduled."""
    out = []
    for (name, start), (_, end) in zip(events, events[1:]):
        window = [r for r in rows if start <= r["t_sched"] < end]
        statuses = collections.Counter(str(r["status"]) if r["status"] is not None else r["outcome"].split(":")[0]
                                       for r in window)
        out.append({"phase": name, "seconds": end - start, "requests": len(window),
                    "statuses": dict(statuses),
                    "latency_useful_ms": LL.dist([r["latency_ms"] for r in window if LL.useful(r)])})
    return out


def first_clean_after(rows, moment, limit_ms):
    return LL.recovery_seconds([r for r in rows if r["t_sched"] >= moment], moment, limit_ms)


def failures(args, config, rep):
    name = f"failures_{config}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 30 + rep)
    fault_file = os.path.join(args.work, name, FAULT_FILE)
    os.environ["FIREWALL_GUARD_FAULT_FILE"] = fault_file
    with Deployment(args, name, "CASCADE_ACTIVE", config, v4=args.with_v4, v5=True,
                    extra=("-s", GUARD_FIXTURE)) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        offsets = LL.poisson_offsets(FAILURE_RATE, args.failure_seconds, SEED + 3000 + rep)
        load = LoadThread(deployment, order.take(len(offsets)), offsets)
        events = []
        mark = lambda label: (events.append((label, time.time())), print(f"  {label}", flush=True))  # noqa: E731
        load.start()
        failure_timeline(args, deployment, mark)
        load_end = time.time()
        # Whatever remains of the schedule keeps running and is accounted as the final phase.
        load.join(args.failure_seconds + CLIENT_TIMEOUT + 30)
        events.append(("after_timeline_end", load.rows[-1]["t_sched"] + 1 if load.rows else time.time()))
        rows = load.rows
        baseline = [r["latency_ms"] for r in rows
                    if dict(events)["baseline"] <= r["t_sched"] < dict(events)["v5_killed"] and LL.useful(r)]
        limit_ms = 2 * (LL.nearest_rank(baseline, 95) or 1000.0)
        stamps = dict(events)
        deployment.collect("timeline", FAILURE_RATE, args.failure_seconds, rows, stamps["baseline"],
                           time.time(), faults_expected=True)
        recovery = {name: first_clean_after(rows, stamps[event], limit_ms)
                    for name, event in (("v5_after_restart", "v5_restarting"),
                                        ("model2_after_kill", "model2_killed"),
                                        ("model2_after_hang", "model2_hung"),
                                        ("canonical_after_kill", "canonical_killed"),
                                        ("v5_after_hang_resumed", "v5_resumed"),
                                        ("guard_after_stop", "guard_stopped"),
                                        ("sink_after_restart", "sink_restarted"),
                                        ("v4_after_return", "return_to_v4"),
                                        ("cascade_after_authority_back", "authority_back"),
                                        ("gateway_after_restart", "gateway_restarting"))
                    if event in stamps}
        deployment.save(rep=rep, order_sha256=order.sha256, events=events, recovery_limit_ms=limit_ms,
                        recovery_seconds=recovery, phases=phases(rows, events), load_end=load_end)
        print(f"  recovery {recovery}", flush=True)


def recovery_run(args, config, mode, rep):
    """The ladder's probe window ends before V4's queue drains: V4 has no admission control and keeps
    working on requests the gateway gave up on. One overload alone, then probes until they are clean
    or the limit is reached."""
    name = f"recovery_{config}_{mode}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 50 + rep)
    with Deployment(args, name, mode, config, **needs(mode)) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        baseline = deployment.step(order, "baseline", 1.0, args.step_seconds, SEED + 5000 + rep)
        limit_ms = 2 * (baseline["client"]["latency_useful_ms"].get("p95") or 1000.0)
        port = deployment.stack.listen_port

        async def scenario():
            offsets = LL.poisson_offsets(args.recovery_rate, args.recovery_load_seconds, SEED + 5100 + rep)
            tasks = await LL.launch("127.0.0.1", port, order.take(len(offsets)), offsets, CLIENT_TIMEOUT)
            await asyncio.sleep(max(0.0, args.recovery_load_seconds - offsets[-1]))
            load_end = time.time()
            probes = []
            while time.time() - load_end < args.recovery_max_seconds:
                offsets = [i / PROBE_RATE for i in range(PROBE_BATCH)]
                probes += await LL.open_loop("127.0.0.1", port, order.take(PROBE_BATCH), offsets,
                                             CLIENT_TIMEOUT, kind="probe")
                if LL.recovery_seconds(probes, load_end, limit_ms) is not None:
                    break
            return await asyncio.gather(*tasks), probes, load_end

        t0 = time.time()
        rows, probes, load_end = asyncio.run(scenario())
        deployment.collect("overload", args.recovery_rate, args.recovery_load_seconds, rows, t0, load_end,
                           l2_rows=rows + probes,
                           probe_client=LL.client_accounting(probes, time.time() - load_end),
                           recovery_limit_ms=limit_ms)
        deployment.write_rows("probe", probes)
        recovery = LL.recovery_seconds(probes, load_end, limit_ms)
        deployment.save(rep=rep, order_sha256=order.sha256, overload_rate=args.recovery_rate,
                        recovery_limit_ms=limit_ms, recovery_seconds=recovery, recovered=recovery is not None,
                        probes=len(probes), load_end=load_end)
        print(f"  {name}: recovery={recovery} after {len(probes)} probes", flush=True)


def return_under_load(args, config, rep):
    """A return to V4 at a rate the cascade carries and V4 does not."""
    name = f"failures_return_load_{config}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 60 + rep)
    pause = args.return_pause
    with Deployment(args, name, "CASCADE_ACTIVE", config, v4=True, v5=True) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        offsets = LL.poisson_offsets(args.return_rate, 3 * pause, SEED + 6000 + rep)
        load = LoadThread(deployment, order.take(len(offsets)), offsets)
        events = []
        mark = lambda label: (events.append((label, time.time())), print(f"  {label}", flush=True))  # noqa: E731
        load.start()
        mark("active")
        time.sleep(pause)
        mark("return_to_v4")
        deployment.stack.rollback(True)
        time.sleep(pause)
        mark("authority_back")
        deployment.stack.rollback(False)
        wait_ready(deployment)
        mark("authority_back_ready")
        load.join(3 * pause + CLIENT_TIMEOUT + 30)
        events.append(("after_timeline_end", load.rows[-1]["t_sched"] + 1 if load.rows else time.time()))
        rows, stamps = load.rows, dict(events)
        baseline = [r["latency_ms"] for r in rows
                    if stamps["active"] <= r["t_sched"] < stamps["return_to_v4"] and LL.useful(r)]
        limit_ms = 2 * (LL.nearest_rank(baseline, 95) or 1000.0)
        deployment.collect("timeline", args.return_rate, 3 * pause, rows, stamps["active"], time.time(),
                           faults_expected=True)
        recovery = {"cascade_after_authority_back": first_clean_after(rows, stamps["authority_back"], limit_ms)}
        deployment.save(rep=rep, order_sha256=order.sha256, events=events, recovery_limit_ms=limit_ms,
                        recovery_seconds=recovery, phases=phases(rows, events))
        print(f"  recovery {recovery}", flush=True)


def observe_failures(args, config, rep):
    """OBSERVE: the same faults must leave V4's answers alone."""
    name = f"observe_failures_{config}_rep{rep}"
    if done(args, name):
        return
    print(f"=== {name}", flush=True)
    order = LL.TrafficOrder(args.cases, SEED + 40 + rep)
    with Deployment(args, name, "CASCADE_OBSERVE", config, v4=True, v5=True) as deployment:
        deployment.metrics_before = deployment.metrics()
        deployment.warmup(order)
        rate, total = 1.0, min(args.failure_seconds, 120)
        offsets = LL.poisson_offsets(rate, total, SEED + 4000 + rep)
        load = LoadThread(deployment, order.take(len(offsets)), offsets)
        events = []
        mark = lambda label: (events.append((label, time.time())), print(f"  {label}", flush=True))  # noqa: E731
        load.start()
        pause = args.failure_pause
        mark("baseline")
        time.sleep(pause)
        mark("v5_killed")
        os.kill(deployment.services["v5"].pid, signal.SIGKILL)
        deployment.services["v5"].wait()
        time.sleep(pause)
        mark("model2_killed")
        for pid in worker_pids(deployment, b"model2_worker"):
            os.kill(pid, signal.SIGKILL)
        time.sleep(pause)
        mark("v5_back")
        deployment.start_service("v5")
        deployment.wait_service("v5")
        wait_ready(deployment)
        mark("v5_ready")
        time.sleep(pause)
        mark("end")
        load.join(total + 2 * CLIENT_TIMEOUT + 30)
        events.append(("after_timeline_end", load.rows[-1]["t_sched"] + 1 if load.rows else time.time()))
        deployment.collect("timeline", rate, total, load.rows, dict(events)["baseline"], time.time(),
                           faults_expected=True)
        deployment.save(rep=rep, order_sha256=order.sha256, events=events,
                        phases=phases(load.rows, events))


def run_order(rep, runs=RUNS):
    order = list(runs)
    random.Random(SEED + 500 + rep).shuffle(order)
    return order


def load_cases(path):
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    cases = []
    for row in rows:
        if row.get("wire_ok"):
            wire = row["wire"].encode("utf-8")
            cases.append({"id": row["id"], "wire_bytes": wire,
                          "wire_sha256": hashlib.sha256(wire).hexdigest(), "cohort": row["cohort"],
                          "label": row["label"]})
    return cases


def write_addendum(args):
    """Phases added after reading the ladder. The protocol it ran under stays as it was."""
    path = os.path.join(args.out, "protocol_addendum.json")
    if os.path.exists(path) or args.candidate_manifest:
        return
    addendum = {
        "schema": "firewall-gateway-load-protocol-addendum/v1",
        "why": "In the ladder V4_ONLY and CASCADE_OBSERVE did not recover within the 45 s probe window, "
               "and the common soak rate is bound by V4, a small fraction of what verified carries.",
        "recovery": {"runs": RECOVERY_RUNS, "repetitions": RECOVERY_REPETITIONS,
                     "baseline": "one step at 1 r/s, whose P95 x 2 is the limit of a clean probe",
                     "overload_rate": args.recovery_rate, "overload_seconds": args.recovery_load_seconds,
                     "probe_rate": PROBE_RATE, "max_seconds": args.recovery_max_seconds},
        "return_under_load": {"config": "verified", "repetitions": RETURN_REPETITIONS,
                              "rate": args.return_rate, "seconds_per_phase": args.return_pause,
                              "phases": ["active", "return_to_v4", "authority_back"]},
        "soak_high": {"modes": SOAK_HIGH_MODES, "repetitions": SOAK_REPETITIONS,
                      "rate": "0.7 x the lowest sustainable rate of V5_ONLY and CASCADE_ACTIVE, verified"}}
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(addendum, fh, indent=2, sort_keys=True, default=list)
        fh.write("\n")


def write_protocol(args):
    path = os.path.join(args.out, "protocol.json")
    if os.path.exists(path):
        return
    with open(args.inputs, "rb") as fh:
        inputs = hashlib.sha256(fh.read()).hexdigest()
    manifests = {}
    for config, manifest_path in args.manifests.items():
        with open(manifest_path, "rb") as fh:
            manifests[config] = {"path": manifest_path, "sha256": hashlib.sha256(fh.read()).hexdigest()}
    profile = None
    if args.profile:
        with open(args.profile, "rb") as fh:
            profile = {"path": args.profile, "sha256": hashlib.sha256(fh.read()).hexdigest()}
    with open(os.path.join(HERE, "load_lib.py"), "rb") as fh:
        meter = hashlib.sha256(fh.read()).hexdigest()
    mix = collections.Counter((c["cohort"], c["label"]) for c in args.cases)
    protocol = {
        "schema": "firewall-gateway-load-protocol/v1",
        "scope": "DEVELOPMENT, HTTP/1.1 cleartext reverse proxy on loopback, inert sink. Not a "
                 "deployment or capacity claim. No threshold selected. No protected set read.",
        "arrivals": "open-loop Poisson, seeded; latency from the scheduled arrival",
        "traffic": {"population": "every wire_ok DEV case", "cases": len(args.cases),
                    "mix": {f"{k[0]}/{k[1]}": v for k, v in sorted(mix.items())},
                    "inputs_sha256": inputs, "order": "shuffled by seed, cycled; same per repetition",
                    "labels_used": False,
                    "note": "Traffic shape only. References are not used and are not ground truth."},
        "seeds": {"base": SEED}, "levels": args.levels, "step_seconds": args.step_seconds,
        "runs": args.runs, "order": "shuffled per repetition with a seeded generator, see `run_order`",
        "run_order": {str(rep): run_order(rep, args.runs) for rep in range(1, 4)},
        "meter_load_lib_sha256": meter,
        "with_v4": args.with_v4,
        "warmup_requests": WARMUP_REQUESTS,
        "client_timeout_s": CLIENT_TIMEOUT, "operating_limits": OPERATING,
        "saturation": {"min_useful_fraction": LL.MIN_USEFUL_FRACTION,
                       "max_useful_p95_ms": LL.MAX_USEFUL_P95_MS,
                       "stop": "two consecutive saturated levels", "status": "descriptive, not an SLO"},
        "recovery": {"overload_seconds": args.overload_seconds, "overload_rate": "1.5 x first saturated",
                     "probe_rate": PROBE_RATE, "probe_seconds": args.probe_seconds,
                     "definition": "10 consecutive useful probes within 2 x the P95 of the first level"},
        "soak": {"seconds": args.soak_seconds, "repetitions": SOAK_REPETITIONS,
                 "rate": "per family, 0.7 x the lowest sustainable rate of its V5 modes and V4_ONLY; "
                         "V4_ONLY also runs at each family's rate, as the baseline of OBSERVE"},
        "audit": {"sample_rates": args.audit_rates, "repetitions": AUDIT_REPETITIONS,
                  "budgets": {name: AUDIT_BUDGETS[name] for name in args.audit_budgets},
                  "dev_rate": args.audit_dev_rate,
                  "permit_rate": args.audit_permit_rate, "seconds": args.audit_seconds,
                  "traffic": "DEV plus synthetic requests of the experimental fixture"},
        "failures": {"rate": FAILURE_RATE, "pause_s": args.failure_pause,
                     "repetitions": args.failure_repetitions,
                     "faults": ["V5 killed", "Model 2 killed", "Model 2 hung", "canonical workers killed",
                                "V5 hung", "guard stopped", "sink killed", "return to V4 with V5 down",
                                "gateway killed"]},
        "manifests": manifests, "verified_profile": profile,
        "status_of_candidates": "EXPERIMENTAL: nothing here approves a profile, a threshold or a "
                                "deployment. 200 ms is aspirational and D36 is not rewritten.",
        "services": "fresh per run; only those the mode needs; V4 is not loaded for V5_ONLY/ACTIVE",
        "doubles": args.doubles}
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(protocol, fh, indent=2, sort_keys=True, default=list)
        fh.write("\n")


def v5_environment(manifest_path=None, profile_path=None):
    """Environment of the V5 service of one configuration. A v2 manifest says where its adapter, recipe
    and runtime are. Nothing is inherited from the shell, so a service never gets a stale profile."""
    env = {}
    if manifest_path:
        v5 = CM.load_manifest(manifest_path).v5
        if v5.adapter_path:
            env.update(FIREWALL_V5_ADAPTER_DIR=v5.adapter_path, FIREWALL_V5_RECIPE=v5.recipe_path)
        if v5.runtime:
            profile_path = v5.runtime.profile_path
    if profile_path:
        with open(profile_path, "rb") as fh:
            env.update(FIREWALL_V5_RUNTIME_PROFILE=os.path.abspath(profile_path),
                       FIREWALL_V5_RUNTIME_PROFILE_SHA256=hashlib.sha256(fh.read()).hexdigest(),
                       FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME="1")
    return env


def configure(parser, args):
    """What runs: the reference and `verified` of the load run, or a delivered candidate."""
    if args.candidate_manifest:
        manifest = CM.load_manifest(args.candidate_manifest)
        if not manifest.is_candidate:
            parser.error("--candidate-manifest needs a v2 manifest")
        args.manifests = {"candidate": args.candidate_manifest}
        args.profile = manifest.v5.runtime.profile_path if manifest.v5.runtime else None
        args.service_env = {"candidate": v5_environment(args.candidate_manifest)}
        args.runs = CANDIDATE_RUNS
        args.high_family = "candidate"
        args.recovery_runs = (("candidate", "CASCADE_ACTIVE"), ("candidate", "V5_ONLY"))
        args.audit_configs = ("candidate",)
        args.audit_budgets = ("unbounded", "bounded")
        args.failure_repetitions = {"candidate": 2}
        if "recovery" in args.phase and not (args.recovery_rate or args.quick):
            parser.error("--recovery-rate: 1.5 x the rate at which this candidate saturated")
        if args.with_v4:
            args.manifests["v4"] = args.candidate_manifest
            args.runs += CANDIDATE_V4_RUNS
            args.recovery_runs += (("candidate", "CASCADE_OBSERVE"),)
        return
    if not (args.manifest and args.verified_manifest and args.verified_profile):
        parser.error("needs --manifest, --verified-manifest and --verified-profile, or --candidate-manifest")
    args.manifests = {"v4": args.manifest, "reference": args.manifest, "verified": args.verified_manifest}
    args.profile = args.verified_profile
    args.service_env = {"verified": v5_environment(profile_path=args.verified_profile)}
    args.runs = RUNS
    args.with_v4 = True
    args.high_family = "verified"
    args.recovery_runs = RECOVERY_RUNS
    args.audit_configs = ("verified", "reference")
    args.audit_budgets = ("unbounded",)
    args.failure_repetitions = FAILURE_REPETITIONS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--manifest", help="reference configuration")
    parser.add_argument("--verified-manifest")
    parser.add_argument("--verified-profile")
    parser.add_argument("--candidate-manifest", help="a v2 manifest; measures this candidate")
    parser.add_argument("--with-v4", action="store_true",
                        help="with a candidate: also V4_ONLY, OBSERVE and the return to V4")
    parser.add_argument("--recovery-rate", type=float, help="1.5 x the rate at which it saturated")
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--phase", action="append", required=True,
                        choices=("ladder", "soak", "soakhigh", "audit", "failures", "recovery"))
    parser.add_argument("--soak-rates", help="reference=R,verified=R, from the ladder")
    parser.add_argument("--soak-high-rate", type=float, help="verified V5_ONLY and CASCADE_ACTIVE")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--doubles", action="store_true", help="dry run of this harness, no GPU")
    parser.add_argument("--double-behavior", default="slow", help="of the V5 double, e.g. serial")
    parser.add_argument("--double-inference-ms", type=float, default=100.0)
    parser.add_argument("--quick", action="store_true", help="dry run durations")
    parser.add_argument("--audit-rates", type=float, nargs="+", help="sample rates of the audit phase")
    parser.add_argument("--audit-seconds", type=float)
    parser.add_argument("--audit-dev-rate", type=float)
    parser.add_argument("--audit-permit-rate", type=float)
    args = parser.parse_args()
    if not args.doubles:
        problem = gpu_gate.refusal()
        if problem:
            print(f"REFUSED: {problem}", flush=True)
            return 4
    configure(parser, args)
    args.levels = LEVELS
    args.step_seconds, args.overload_seconds, args.probe_seconds = STEP_SECONDS, OVERLOAD_SECONDS, PROBE_SECONDS
    args.soak_seconds, args.audit_seconds = SOAK_SECONDS, args.audit_seconds or AUDIT_SECONDS
    args.audit_dev_rate = args.audit_dev_rate or AUDIT_DEV_RATE
    args.audit_permit_rate = args.audit_permit_rate or AUDIT_PERMIT_RATE
    args.audit_rates = tuple(args.audit_rates) if args.audit_rates else AUDIT_RATES
    args.failure_seconds, args.failure_pause = FAILURE_SECONDS, 12.0
    args.warmup_requests = WARMUP_REQUESTS
    args.recovery_rate, args.recovery_load_seconds = args.recovery_rate or RECOVERY_RATE, RECOVERY_LOAD_SECONDS
    args.recovery_max_seconds, args.return_rate, args.return_pause = RECOVERY_MAX_SECONDS, RETURN_RATE, RETURN_PAUSE
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))   # so `with Deployment` closes what it opened
    if args.quick:
        # A dry run of the harness: low rates, so it leaves other work on this machine alone.
        args.levels = (2, 4)
        args.repetitions = 1
        args.step_seconds, args.overload_seconds, args.probe_seconds = 4, 4, 14
        args.soak_seconds, args.audit_seconds, args.failure_pause = 8, 6, 3.0
        args.failure_seconds = 75
        args.audit_dev_rate, args.audit_permit_rate = 1.0, 2.0
        args.warmup_requests = 3
        args.recovery_rate, args.recovery_load_seconds, args.recovery_max_seconds = 5.0, 4, 30
        args.return_rate, args.return_pause = 3.0, 5.0
    os.makedirs(os.path.join(args.out, "rows"), exist_ok=True)
    os.makedirs(os.path.join(args.out, "configs"), exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    args.cases = load_cases(args.inputs)
    write_protocol(args)
    write_addendum(args)
    try:
        for phase in args.phase:
            if phase == "ladder":
                for rep in range(1, args.repetitions + 1):
                    for config, mode in run_order(rep, args.runs):
                        ladder(args, config, mode, rep)
            elif phase == "soak":
                rates = dict(item.split("=") for item in args.soak_rates.split(","))
                for rep in range(1, SOAK_REPETITIONS + 1):
                    for family, rate in rates.items():
                        for config, mode in run_order(rep, args.runs):
                            if config in ("v4", family):
                                soak(args, family, family if config != "v4" else "v4", mode, rep,
                                     float(rate))
            elif phase == "soakhigh":
                for rep in range(1, SOAK_REPETITIONS + 1):
                    for mode in SOAK_HIGH_MODES:
                        soak(args, args.high_family, args.high_family, mode, rep, args.soak_high_rate,
                             prefix="soakhigh")
            elif phase == "recovery":
                for rep in range(1, min(args.repetitions, RECOVERY_REPETITIONS) + 1):
                    for config, mode in args.recovery_runs:
                        recovery_run(args, config, mode, rep)
                    if args.with_v4:
                        return_under_load(args, args.high_family, rep)
            elif phase == "audit":
                for rep in range(1, min(args.repetitions, AUDIT_REPETITIONS) + 1):
                    for config in args.audit_configs:
                        for offset in range(len(args.audit_rates)):
                            rate = args.audit_rates[(rep + offset) % len(args.audit_rates)]
                            for budget in args.audit_budgets:
                                audit_cell(args, config, rate, rep, budget)
            elif phase == "failures":
                for config, repetitions in args.failure_repetitions.items():
                    for rep in range(1, min(args.repetitions, repetitions) + 1):
                        failures(args, config, rep)
                        if args.with_v4:
                            observe_failures(args, config, rep)
    except ForeignGpuProcess as exc:
        print(f"STOPPED: a compute process that is not ours appeared: {exc}", flush=True)
        return 3
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
