"""
Operational / load behavior for the cascade lab: V5 service concurrency and
saturation (bounded queue -> 503), throughput, and a measured real-gateway
end-to-end latency sample (L2/L3) through the full cascade.

Run in `.venv-analyzer` with the V5 service on :8001:
    .venv-analyzer/bin/python scripts/cascade_lab/operational_check.py --out <dir>
"""
import argparse
import concurrent.futures as cf
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "data_plane"))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import cascade as C          # noqa: E402
import cascade_runtime as RT  # noqa: E402
import fast_path as fp        # noqa: E402
import model2_decider as MD   # noqa: E402
import lab_server as L        # noqa: E402

FINAL = os.path.join(REPO, "model-output-model2/final/v4-d82-20261027T052308Z")
POL = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies")
SHA_B = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


def pct(v, p):
    import math
    s = sorted(v)
    return s[max(1, math.ceil(p / 100 * len(s))) - 1] if s else None


def concurrency_test(v5_url, canonical_text, n, workers):
    """Fire `n` requests with `workers` threads at the V5 service; count statuses."""
    client = RT.V5HttpClient(v5_url, timeout_s=60)
    results = []

    def one(_):
        t0 = time.perf_counter()
        reply = client(canonical_text)
        return reply.status, reply.detail, (time.perf_counter() - t0) * 1000

    t_start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for status, detail, ms in ex.map(one, range(n)):
            results.append((status, detail, ms))
    wall = time.perf_counter() - t_start
    oks = [m for s, d, m in results if s in ("ok", "invalid")]
    saturated = sum(1 for s, d, m in results if s == "error" and d in ("http_503",))
    errors = sum(1 for s, d, m in results if s == "error")
    return {
        "requests": n, "workers": workers, "wall_s": wall,
        # throughput_rps counts EVERY response, including 503s from a saturated
        # service — it is NOT a useful-work rate. goodput_rps counts only the
        # requests that got a real classification. Report both, plus the error
        # and saturation rates, so the saturated regime is never read as capacity.
        "throughput_rps": n / wall if wall else None,
        "goodput_rps": len(oks) / wall if wall else None,
        "ok_or_invalid": len(oks), "errors": errors, "saturated_503": saturated,
        "error_rate": errors / n if n else None,
        "saturation_rate_503": saturated / n if n else None,
        "latency_ms": {"p50": pct(oks, 50), "p95": pct(oks, 95), "max": max(oks) if oks else None},
        "provenance": "measured; service max_inflight bounds in-flight, excess -> 503 "
                      "(fail-closed). throughput_rps INCLUDES 503s; use goodput_rps for "
                      "useful work. latency percentiles are over successful responses only.",
    }


def gateway_latency_sample(v5_url, requests):
    """Run a small set through the REAL gateway (real Model 2 + V5) and record
    measured gateway_ms, applied action, stage, upstream_received (L2)."""
    decider = MD.Model2Decider.from_policy_file(
        os.path.join(FINAL, "baseline34.json"), expected_sha256=SHA_B,
        policy_path=os.path.join(POL, "model2_lab_baseline34.json"))
    fp_policy = fp.load_policy(os.path.join(POL, "fast_path_lab_app.json"))
    v5 = RT.V5HttpClient(v5_url, timeout_s=30)
    router = C.CascadeRouter(
        C.CascadeConfig(mode=C.CASCADE_ACTIVE, fast_path_policy=fp_policy),
        fast_path_evaluate=fp.safe_evaluate, model2_decide=decider.decide,
        v5_classify=v5, make_fast_path_input=RT.make_fast_path_input)
    logs = []
    sink = L.UpstreamSink(); sink.start()
    gw = L.CascadeGateway(router, L.GatewayConfig(upstream_addr=(sink.host, sink.port),
                                                  log_sink=logs.append))
    gw.start()
    try:
        for raw in requests:
            with socket.create_connection((gw.host, gw.port), timeout=30) as s:
                s.sendall(raw)
                while s.recv(4096):
                    pass
    finally:
        gw.stop(); sink.stop()
    recs = [{"stage": r["deciding_stage"], "applied": r["applied"],
             "upstream_received": r.get("upstream_received"),
             "gateway_ms": r.get("gateway_ms")} for r in logs]
    gms = [r["gateway_ms"] for r in recs if r["gateway_ms"] is not None]
    return {"records": recs,
            "gateway_ms": {"n": len(gms), "p50": pct(gms, 50), "p95": pct(gms, 95),
                           "max": max(gms) if gms else None},
            "provenance": "measured end-to-end gateway incl. transport, canonical, stages, "
                          "enforcement. This is an UNCONTROLLED operational sample, NOT the "
                          "D31/D32/D36 benchmark: no warm-up/steady-state separation and the "
                          "mix includes zero-generation rejections (early BLOCK / protocol). "
                          "Make NO D36-compliance claim from these numbers."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v5-url", default="http://127.0.0.1:8001")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    benign = "GET /catalog/widgets HTTP/1.1\n"
    out = {"concurrency": {}, "gateway_latency": {}}
    for workers in (1, 4, 16):
        out["concurrency"]["workers_%d" % workers] = concurrency_test(
            args.v5_url, benign, n=48, workers=workers)

    gw_reqs = [
        b"GET /healthz HTTP/1.1\r\nHost: lab.local\r\n\r\n",                      # fast_allow
        b"GET /download?file=..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: f.local\r\n\r\n",  # model2 block
        b"GET /catalog/widgets HTTP/1.1\r\nHost: shop.local\r\n\r\n",            # v5 allow
        b"GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: s.local\r\n\r\n",  # v5 block
    ] * 8
    out["gateway_latency"] = gateway_latency_sample(args.v5_url, gw_reqs)

    with open(os.path.join(args.out, "operational.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps({"concurrency": out["concurrency"],
                      "gateway_latency": out["gateway_latency"]["gateway_ms"]}, indent=2))


if __name__ == "__main__":
    main()
