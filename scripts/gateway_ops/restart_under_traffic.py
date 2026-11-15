"""
Does the gateway survive being restarted while requests keep arriving? No model, no GPU: V5 is a double,
because what is under test happens before any model is asked.

    .venv-dataplane/bin/python scripts/gateway_ops/restart_under_traffic.py --manifest <manifest.json> \
        --work <private directory> --out <new file>

mitmdump listens before its startup has finished, and it exits if anything logs an error in that window.
The first requests after a restart arrive exactly there, while the gateway is still not ready.
"""
import argparse
import collections
import json
import os
import signal
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import live_check as LC  # noqa: E402
import live_stack as L   # noqa: E402

RESTARTS = 20
SETTLE_SECONDS = 6.0
READY_TIMEOUT = 15.0


class Traffic(threading.Thread):
    """Connects and sends as fast as it can. Refused connections are the point: it keeps trying."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.stop_event, self.answers = port, threading.Event(), 0

    def run(self):
        while not self.stop_event.is_set():
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5) as s:
                    s.sendall(LC.BENIGN)
                    if s.recv(16):
                        self.answers += 1
            except OSError:
                time.sleep(0.001)


def attempt(stack, traffic_port):
    """One kill and restart with traffic running. Where did it end up?"""
    stack.gateway_proc.send_signal(signal.SIGKILL)
    stack.gateway_proc.wait()
    traffic = Traffic(traffic_port)
    traffic.start()
    try:
        stack.start_gateway()
        deadline = time.monotonic() + SETTLE_SECONDS
        while time.monotonic() < deadline and stack.gateway_proc.poll() is None:
            time.sleep(0.05)
        if stack.gateway_proc.poll() is not None:
            return "gateway_exited"
        try:
            stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        except TimeoutError:
            return "alive_never_ready"
        return "ready"
    finally:
        traffic.stop_event.set()
        traffic.join(2)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--restarts", type=int, default=RESTARTS)
    args = parser.parse_args(argv)
    stack = L.Stack(os.path.join(args.work, "restart"), mode="CASCADE_ACTIVE", manifest=args.manifest)
    stack.start()
    outcomes = []
    try:
        stack.wait_ready(timeout=30.0, require_cascade=True)
        for index in range(args.restarts):
            outcomes.append(attempt(stack, stack.listen_port))
            print(index + 1, outcomes[-1], flush=True)
            if outcomes[-1] == "gateway_exited":   # the next attempt needs one running to kill
                stack.start_gateway()
                stack.wait_port(stack.listen_port)
                stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
    finally:
        stack.stop()
    document = {"schema": "firewall-restart-under-traffic/v1", "v5": "double", "restarts": args.restarts,
                "outcomes": dict(collections.Counter(outcomes)), "sequence": outcomes}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(document["outcomes"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
