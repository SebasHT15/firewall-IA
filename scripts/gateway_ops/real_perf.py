"""
Isolated, layered measurement of one V5 configuration through the gateway.

    .venv-dataplane/bin/python scripts/gateway_ops/real_perf.py --out <evidence dir> --work <private dir> \
        --manifest <manifest.json> --inputs <private inputs.jsonl> --benchmark-ids <protocol.json>

ISOLATION. Each run owns the GPU: nothing else may be loaded, V4 is not started, and a fresh V5 process
serves exactly one configuration. Runs are in the fixed balanced order of `ORDER`. A run refuses to
start if another compute process is on the GPU. The desktop's small graphics use cannot be removed;
it is sampled in the telemetry.

LAYERS. They are measured, never derived by subtracting percentiles:

  inference   `pipeline_ms` from the service: encode + transfer + generate + decode + parse
  generation  `generate_ms` from the service
  queue       `queue_wait_ms` from the service: wait for the GPU lock
  service     `service_ms` from the service: inside the handler
  API client  round trip to /classify, without the gateway
  V5 hop      the router's own time around the V5 call (`timings_ms.v5_ms`)
  gateway     `gateway_ms`: hook start to the action, including the V5 hop
  own cost    per request, gateway_ms minus the V5 hop of that same request
  client      raw socket connect to full response, through everything, including the sink

Concurrency 1 is the primary measurement. A short concurrency 4 pass shows queueing and is not a
capacity figure. Percentiles are nearest rank, with no outlier removed. First requests after the load
are separated. Nothing here is a D36 verdict unless it is the steady inference layer at concurrency 1.

Records keep ids, codes and numbers. No request content is written to `--out`.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import gpu_gate            # noqa: E402
import live_check as LC    # noqa: E402
import live_stack as L     # noqa: E402

PROFILES = os.path.join(REPO, "reports/v5/successor-2026-10-30/runtime/profiles")
ORDER = (("reference", 1), ("nf4", 1), ("nf4", 2), ("reference", 2), ("reference", 3), ("nf4", 3))
CONCURRENT_REQUESTS = 48
WARMUP = 4
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OVERRIDES = dict(v4_timeout=5.0, v5_timeout=30.0, deadline=60.0, max_inflight=8, max_waiting=64)


def nearest_rank(values, p):
    ordered = sorted(values)
    return ordered[max(1, math.ceil(p / 100 * len(ordered))) - 1] if ordered else None


def dist(values):
    values = [v for v in values if v is not None]
    if not values:
        return {"n": 0}
    return {"n": len(values), "mean": sum(values) / len(values), "p50": nearest_rank(values, 50),
            "p95": nearest_rank(values, 95), "p99": nearest_rank(values, 99), "min": min(values),
            "max": max(values)}


def gpu_compute_processes():
    out = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                          "--format=csv,noheader"], capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line.strip() and "ptyxis" not in line]


class Telemetry:
    def __init__(self, path):
        self.path, self.stop_event = path, threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        with open(self.path, "x", encoding="utf-8") as fh:
            while not self.stop_event.is_set():
                out = subprocess.run(
                    ["nvidia-smi", "--query-gpu=temperature.gpu,clocks.sm,utilization.gpu,memory.used,power.draw",
                     "--format=csv,noheader,nounits"], capture_output=True, text=True).stdout.strip()
                fh.write(json.dumps({"utc": time.time(), "csv": out}) + "\n")
                fh.flush()
                self.stop_event.wait(1.0)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop_event.set()
        self.thread.join(5)


def start_v5(config, port, log_path):
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONDONTWRITEBYTECODE="1",
               TOKENIZERS_PARALLELISM="false")
    for name in ("FIREWALL_V5_RUNTIME_PROFILE", "FIREWALL_V5_RUNTIME_PROFILE_SHA256",
                 "FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME"):
        env.pop(name, None)
    if config != "reference":
        path = os.path.join(PROFILES, f"{config}.EXPERIMENTAL.json")
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        env.update(FIREWALL_V5_RUNTIME_PROFILE=path, FIREWALL_V5_RUNTIME_PROFILE_SHA256=digest,
                   FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME="1")
    log = open(log_path, "xb")
    proc = subprocess.Popen(["/usr/bin/python3.12", "-B", "-m", "uvicorn", "--app-dir",
                             os.path.join(REPO, "control_plane"), "v5_classifier_api:app", "--host",
                             "127.0.0.1", "--port", str(port)], cwd=REPO, stdout=log,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)
    log.close()
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("V5 exited during load")
        status, body = L.http_get(url + "/health", timeout=1.0)
        if status == 200 and json.loads(body).get("model_loaded"):
            return proc, url, json.loads(body)
        time.sleep(0.2)
    proc.terminate()
    raise TimeoutError("V5 did not load")


def classify(url, text):
    request = urllib.request.Request(url + "/classify", method="POST",
                                     data=json.dumps({"canonical_request": text}).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    started = time.perf_counter()
    with OPENER.open(request, timeout=60) as resp:
        body = json.loads(resp.read())
    body["client_ms"] = (time.perf_counter() - started) * 1000
    return body


API_FIELDS = ("status", "decision", "invalid_reason", "pipeline_ms", "generate_ms", "queue_wait_ms",
              "service_ms", "generated_tokens", "prompt_tokens", "client_ms")


def api_row(row_id, body, phase):
    return {"id": row_id, "phase": phase, **{k: body.get(k) for k in API_FIELDS}}


def direct_pass(url, rows):
    out = [api_row("cold", classify(url, rows[0]["canonical_text"]), "cold")]
    for row in rows[1:1 + WARMUP]:
        out.append(api_row(row["id"], classify(url, row["canonical_text"]), "warmup"))
    for row in rows:
        out.append(api_row(row["id"], classify(url, row["canonical_text"]), "benchmark"))
    return out


def direct_concurrent(url, rows):
    work = [rows[i % len(rows)] for i in range(CONCURRENT_REQUESTS)]
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        return [api_row(r["id"], b, "concurrent4")
                for r, b in zip(work, pool.map(lambda r: classify(url, r["canonical_text"]), work))]


def gateway_pass(stack, rows, phase):
    """Sequential. Pairs each request with its decision record through the JSONL order."""
    path = os.path.join(stack.workdir, "decisions.jsonl")
    position = 0
    out = []
    for row in rows:
        started = time.perf_counter()
        status = stack.send([row["wire"].encode("utf-8")], timeout=60.0)[0]
        client_ms = (time.perf_counter() - started) * 1000
        record = None
        deadline = time.monotonic() + 3.0
        while record is None and time.monotonic() < deadline:
            with open(path, encoding="utf-8") as fh:
                fh.seek(position)
                while True:
                    line = fh.readline()
                    if not line.endswith("\n"):
                        break
                    position = fh.tell()
                    parsed = json.loads(line)
                    if parsed.get("kind") == "decision":
                        record = parsed
            if record is None:
                time.sleep(0.002)
        record = record or {}
        out.append(gateway_row(row["id"], phase, status, client_ms, record))
    return out


def gateway_row(row_id, phase, status, client_ms, record):
    timings = record.get("timings_ms") or {}
    stages = record.get("stage_ms") or {}
    hop = timings.get("v5_ms")
    return {"id": row_id, "phase": phase, "http_status": status, "client_ms": client_ms,
            "stage": record.get("deciding_stage"), "applied": record.get("applied"),
            "gateway_ms": record.get("gateway_ms"), "v5_hop_ms": hop,
            "generate_ms": (record.get("v5") or {}).get("generate_ms"),
            "binding_ms": stages.get("binding"), "canonical_ms": stages.get("canonical"),
            "fast_path_ms": timings.get("fast_path_ms"), "model2_ms": timings.get("model2_ms"),
            "own_ms": (record["gateway_ms"] - (hop or 0)) if record.get("gateway_ms") is not None else None}


def gateway_concurrent(stack, rows):
    work = [rows[i % len(rows)] for i in range(CONCURRENT_REQUESTS)]

    def one(row):
        started = time.perf_counter()
        status = stack.send([row["wire"].encode("utf-8")], timeout=60.0)[0]
        return {"id": row["id"], "phase": "gateway_concurrent4", "http_status": status,
                "client_ms": (time.perf_counter() - started) * 1000}

    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        out = list(pool.map(one, work))
    time.sleep(0.5)
    records = [r for r in stack.records() if r.get("kind") == "decision"][-CONCURRENT_REQUESTS:]
    return out, [gateway_row("", "gateway_concurrent4", None, None, r) for r in records]


def layer_summary(api, gateway_v5only, gateway_active, api_c4, gw_c4, gw_c4_records):
    bench = [r for r in api if r["phase"] == "benchmark" and (r["generated_tokens"] or 0) > 0]
    v5_rows = [r for r in gateway_v5only if r["stage"] == "v5" and r["applied"] is not None]
    summary = {
        "cold": [r for r in api if r["phase"] == "cold"], "warmup_client_ms": dist(
            [r["client_ms"] for r in api if r["phase"] == "warmup"]),
        "concurrency_1": {
            "N_generating": len(bench),
            "inference_pipeline_ms": dist([r["pipeline_ms"] for r in bench]),
            "generation_ms": dist([r["generate_ms"] for r in bench]),
            "queue_wait_ms": dist([r["queue_wait_ms"] for r in bench]),
            "service_ms": dist([r["service_ms"] for r in bench]),
            "api_client_ms": dist([r["client_ms"] for r in bench]),
            "v5_hop_ms": dist([r["v5_hop_ms"] for r in v5_rows]),
            "gateway_ms_v5_route": dist([r["gateway_ms"] for r in v5_rows]),
            "gateway_own_ms_v5_route": dist([r["own_ms"] for r in v5_rows]),
            "binding_ms": dist([r["binding_ms"] for r in gateway_active]),
            "canonical_ms": dist([r["canonical_ms"] for r in gateway_active]),
            "model2_ms": dist([r["model2_ms"] for r in gateway_active]),
            "client_ms_v5_only_gateway": dist([r["client_ms"] for r in v5_rows])},
        "active_routes_concurrency_1": {},
        "concurrency_4_not_capacity": {
            "api_client_ms": dist([r["client_ms"] for r in api_c4]),
            "queue_wait_ms": dist([r["queue_wait_ms"] for r in api_c4]),
            "inference_pipeline_ms": dist([r["pipeline_ms"] for r in api_c4]),
            "gateway_client_ms": dist([r["client_ms"] for r in gw_c4]),
            "gateway_ms": dist([r["gateway_ms"] for r in gw_c4_records]),
            "gateway_statuses": {str(s): sum(1 for r in gw_c4 if r["http_status"] == s)
                                 for s in {r["http_status"] for r in gw_c4}}}}
    for stage in sorted({r["stage"] for r in gateway_active if r["stage"]}):
        rows = [r for r in gateway_active if r["stage"] == stage]
        summary["active_routes_concurrency_1"][stage] = {
            "N": len(rows), "client_ms": dist([r["client_ms"] for r in rows]),
            "gateway_ms": dist([r["gateway_ms"] for r in rows])}
    return summary


def one_run(args, config, run, rows):
    name = f"{config}_run{run}"
    print(f"=== {name}", flush=True)
    others = gpu_compute_processes()
    if others:
        raise RuntimeError(f"GPU not isolated: {others}")
    manifest = args.manifest
    if config != "reference":
        with open(args.manifest, encoding="utf-8") as fh:
            document = json.load(fh)
        with open(os.path.join(PROFILES, f"{config}.EXPERIMENTAL.json"), "rb") as fh:
            document["v5"]["runtime_profile_sha256"] = hashlib.sha256(fh.read()).hexdigest()
        document["manifest_id"] += f"-{config}-profile"
        manifest = os.path.join(args.work, f"{name}_manifest.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(document, fh)

    port = L.free_port()
    with Telemetry(os.path.join(args.out, f"{name}_gpu.jsonl")):
        proc, url, health = start_v5(config, port, os.path.join(args.work, f"{name}_v5.log"))
        try:
            args.v5_url, args.v4_url = url, f"http://127.0.0.1:{L.free_port()}"   # V4 is not loaded
            api = direct_pass(url, rows)
            api_c4 = direct_concurrent(url, rows)
            stack = LC.make_stack(args, f"{name}_v5only", mode="V5_ONLY", overrides=OVERRIDES,
                                  manifest=manifest)
            stack.start()
            try:
                stack.wait_ready(timeout=30.0)
                gw_v5 = gateway_pass(stack, rows, "gateway_v5only")
            finally:
                stack.stop()
            stack = LC.make_stack(args, f"{name}_active", mode="CASCADE_ACTIVE", overrides=OVERRIDES,
                                  manifest=manifest)
            stack.start()
            try:
                stack.wait_ready(timeout=30.0)
                gw_active = gateway_pass(stack, rows, "gateway_active")
                gw_c4, gw_c4_records = gateway_concurrent(stack, rows)
            finally:
                stack.stop()
        finally:
            proc.terminate()
            proc.wait(timeout=20)
    with open(os.path.join(args.out, f"{name}.jsonl"), "x", encoding="utf-8") as fh:
        for row in api + api_c4 + gw_v5 + gw_active + gw_c4:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return {"config": config, "run": run, "runtime_settings": health.get("runtime_settings"),
            "runtime_profile": health.get("runtime_profile"), "load_s": health.get("load_s"),
            "layers": layer_summary(api, gw_v5, gw_active, api_c4, gw_c4, gw_c4_records)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--benchmark-ids", required=True)
    parser.add_argument("--limit", type=int, default=0, help="trial only: fewer inputs")
    parser.add_argument("--order", help="trial only: config:run,config:run")
    args = parser.parse_args()
    problem = gpu_gate.refusal()
    if problem:
        print(f"REFUSED: {problem}", flush=True)
        return 4
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    with open(args.benchmark_ids, encoding="utf-8") as fh:
        ids = json.load(fh)["benchmark_ids"]
    with open(args.inputs, encoding="utf-8") as fh:
        by_id = {r["id"]: r for r in map(json.loads, fh)}
    rows = [by_id[i] for i in ids]
    if args.limit:
        rows = rows[:args.limit]
    order = ORDER
    if args.order:
        order = tuple((c, int(r)) for c, r in (item.split(":") for item in args.order.split(",")))
    protocol = {
        "schema": "firewall-gateway-layered-perf/v1", "order": order, "benchmark_ids_N": len(rows),
        "benchmark_ids_source": "reports/v5/successor-2026-10-30/runtime/protocol.json",
        "warmup": WARMUP, "concurrent_requests": CONCURRENT_REQUESTS, "percentile": "nearest rank",
        "isolation": "one fresh V5 process and configuration per run; V4 not loaded",
        "scope": "DEVELOPMENT measurement on this machine; not a deployment or capacity claim"}
    with open(os.path.join(args.out, "protocol.json"), "x", encoding="utf-8") as fh:
        json.dump(protocol, fh, indent=2, sort_keys=True)
    results = [one_run(args, config, run, rows) for config, run in order]
    with open(os.path.join(args.out, "layers.json"), "x", encoding="utf-8") as fh:
        json.dump({**protocol, "runs": results}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
