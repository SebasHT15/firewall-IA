"""
Failures of each component behind the TLS front, with a V5 DOUBLE, and cleanup afterwards.

    .venv-dataplane/bin/python -B scripts/local_stack/failure_check.py --config scripts/local_stack/stack.example.json --out <new evidence dir> --work <new private dir>

Injected through the forwarder in front of V5 (scripts/gateway_ops/fault_proxy.py): an error, an
unusable answer and a hang longer than the gateway's V5 timeout. Then the application container is
stopped and started again, and finally the gateway is killed. For each, a request through the front must
not reach the application, must be answered by the layer that failed (gateway fail-closed, or the front
when the gateway is gone), and must be attributed to it by the logs. `down` must then clean everything,
including components that already died.
"""
import argparse
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import app_check as A            # noqa: E402
import harness as H              # noqa: E402
import stack as S                # noqa: E402
import transport_check as TC     # noqa: E402
import wire_clients as WC        # noqa: E402

AUTHORITY = "notes.fwlab.test"


def probe(state, proxy, label, expect_app):
    app, dec, front = (TC.Tail(state[k]) for k in ("app_log", "gateway_decisions", "front_access_log"))
    for t in (app, dec, front):
        t.mark()
    calls = proxy.classify_calls
    ctx = WC.tls_context(state["pki"]["ca_cert"], ("http/1.1",))
    started = time.perf_counter()
    res = WC.h1_exchange(state["ports"]["front_tls"], WC.build_h1("GET", "/", AUTHORITY), tls=ctx,
                         server_hostname=AUTHORITY, timeout=15)
    elapsed = (time.perf_counter() - started) * 1000
    time.sleep(1.0)
    app_lines = app.new()
    decisions = [r for r in dec.new() if r.get("kind") == "decision"]
    front_lines = front.new()
    f = front_lines[-1] if front_lines else {}
    # nginx reports the gateway's answer in upstream_status; when it could not connect, there is no
    # connect time ("-" or empty) and the 502 is its own.
    front_own = bool(f) and f.get("upstream_connect_time") in ("", "-")
    layer = ("application" if app_lines else "front" if front_own else
             "firewall" if decisions and decisions[-1].get("applied") == "DENY" else
             "upstream_unreachable" if decisions and decisions[-1].get("applied") == "FORWARD" else
             "gateway_no_record")
    row = {"probe": label, "status": res["status"], "elapsed_ms": round(elapsed, 1), "layer": layer,
           "app_lines": len(app_lines), "v5_calls": proxy.classify_calls - calls,
           "gateway": [{"applied": d.get("applied"), "stage": d.get("deciding_stage"), "reason": d.get("reason"),
                        "http_status": d.get("http_status")} for d in decisions],
           "front": {k: f.get(k) for k in ("status", "upstream_status", "upstream_connect_time")} if f else None,
           "firewall_body": (res["body"] or b"").startswith(A.FIREWALL_BODIES)}
    row["passed"] = bool(app_lines) == expect_app
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    if os.path.exists(args.out) or os.path.exists(args.work):
        sys.exit("refusing to reuse --out or --work")
    os.makedirs(args.out)
    holder, rows = {}, []
    with H.doubled_stack(args.config, args.work, "app", (), holder) as (state, proxy):
        identity = state["identity"]
        rows.append(probe(state, proxy, "baseline", True))
        rows[-1]["passed"] &= rows[-1]["status"] == 200
        for fault in ("error500", "invalid_no_eos", "hang"):
            proxy.hang_seconds = 6.0
            proxy.fault = fault
            row = probe(state, proxy, f"v5_{fault}", False)
            row["passed"] &= row["layer"] == "firewall" and row["status"] in (403, 503)
            rows.append(row)
            proxy.fault = None
        rows.append(probe(state, proxy, "v5_recovered", True))
        app = next(c for c in state["components"] if c["name"] == "app")
        S.docker("stop", "-t", "2", app["container"])
        row = probe(state, proxy, "app_stopped", False)
        row["passed"] &= row["status"] == 502 and row["layer"] == "upstream_unreachable"
        rows.append(row)
        S.docker("start", app["container"])
        S.wait_until(lambda: S.http_get(state["endpoints"]["app_direct"] + "/healthz", timeout=1)[0] == 200, 20,
                     "app restart")
        rows.append(probe(state, proxy, "app_restarted", True))
        gw = next(c for c in state["components"] if c["name"] == "gateway")
        os.killpg(gw["pgid"], signal.SIGKILL)
        time.sleep(1.0)
        S.reap(gw["pid"])
        row = probe(state, proxy, "gateway_killed", False)
        row["passed"] &= row["layer"] == "front" and row["status"] == 502
        rows.append(row)
    clean = holder.get("clean") or {}
    passed = all(r["passed"] for r in rows) and clean.get("clean", False)
    doc = {"schema": "firewall-local-stack-failure-check/v1", "created_utc": time.time(),
           "kind": "MECHANISM_CHECK_WITH_V5_DOUBLE", "identity": identity, "passed": passed, "probes": rows,
           "clean_after": clean}
    with open(os.path.join(args.out, "FAILURES.json"), "x", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({"passed": passed, "probes": [{k: r[k] for k in ("probe", "status", "layer", "passed",
                                                                      "elapsed_ms")} for r in rows],
                      "clean": clean.get("clean")}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
