"""
Can a client of the gateway receive a cut body? Real mitmdump, real canonical workers, guard and Model 2
on CPU, V4/V5 doubles, and an upstream that fails inside its response. No GPU.

    .venv-dataplane/bin/python scripts/gateway_ops/upstream_cut_probe.py --manifest <manifest.json> \
        --work <private dir> --out <file that does not exist>

A mechanism check of the corrected client, and of how the gateway answers while it stays alive. It says
nothing about any model.
"""
import argparse
import asyncio
import collections
import hashlib
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import live_stack as L  # noqa: E402
import load_lib as LL   # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "faulty_upstream.py")
WIRE = b"GET /catalog/widgets HTTP/1.1\r\nHost: shop.local\r\n\r\n"
CASE = {"id": "probe", "wire_bytes": WIRE, "wire_sha256": hashlib.sha256(WIRE).hexdigest()}
REQUESTS = 12


class FaultyStack(L.Stack):
    behavior = "cut"

    def start_sink(self):
        self._spawn("faulty_upstream", [L.PYTHON, "-I", FIXTURE, "--port", str(self.sink_port),
                                        "--behavior", self.behavior])


def summary(rows):
    return {"requests": len(rows), "statuses": dict(collections.Counter(str(r["status"]) for r in rows)),
            "outcomes": dict(collections.Counter(r["outcome"].split(":")[0] for r in rows)),
            "incomplete_body": sum(r["outcome"] == "incomplete_body" for r in rows),
            "useful": sum(LL.useful(r) for r in rows)}


def run(work, manifest, mode, behavior, kill):
    name = f"{mode}_{behavior}{'_gateway_killed' if kill else ''}"
    stack = FaultyStack(os.path.join(work, name), mode=mode, manifest=manifest)
    stack.behavior = behavior
    stack.start()
    try:
        if mode == "V4_ONLY":      # no runtime, so no readiness to wait for
            time.sleep(1.0)
        else:
            stack.wait_ready(timeout=30.0)

        async def traffic():
            tasks = await LL.launch("127.0.0.1", stack.listen_port, [CASE] * REQUESTS,
                                    [i * 0.02 for i in range(REQUESTS)], 4.0, kind="probe")
            if kill:
                await asyncio.sleep(0.5)
                stack.gateway_proc.send_signal(signal.SIGKILL)
            return await asyncio.gather(*tasks)

        rows = asyncio.run(traffic())
    finally:
        stack.stop()
    return name, summary(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    results = {}
    for mode, behavior, kill in (("CASCADE_ACTIVE", "cut", False), ("CASCADE_ACTIVE", "reset", False),
                                 ("CASCADE_ACTIVE", "stall", True), ("V4_ONLY", "cut", False),
                                 ("V4_ONLY", "stall", True)):
        name, result = run(args.work, args.manifest, mode, behavior, kill)
        results[name] = result
        print(name, result, flush=True)
    document = {"schema": "firewall-upstream-cut-probe/v1", "utc": time.time(),
                "scope": "real mitmdump with V4 and V5 doubles; upstream fixture answers 3 of 10 body "
                         "bytes; mechanism only", "results": results,
                "client_saw_a_cut_body": any(r["incomplete_body"] for r in results.values())}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
