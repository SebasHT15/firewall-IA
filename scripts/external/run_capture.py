"""External Test v1 — Phase C DRAFT capture orchestrator (runs inside the generator).

Drives ALL benign and BLOCK flows through the CAPTURE proxy in one run, with the firewall
data plane and control plane absent from the path (D37). It records, for every flow, the
window of capture-file lines it produced, so label_candidates.py can attach ground truth by
OFFSET rather than by any marker inside a request under test (protocol 11).

How the offset windows are found without markers:
    the capture proxy appends one flushed line per request to a shared file. This
    orchestrator reads that file's line count immediately before and after each flow. The
    difference is the flow's window — and, crucially, it INCLUDES browser sub-resource
    requests, which the driver itself never sees. Synchronous clients (curl, httpx) and
    Playwright's wait-for-load, plus a short settle, ensure a flow's records are all flushed
    before the next flow starts.

For the enumerable flows (api/unseen/attacks) each Spec produces exactly one request
(redirects are not followed), so the window size MUST equal the number of specs; the summary
flags any mismatch. Browser flows are variable and are captured whole.

Run (single command; lab-app + capture-proxy must already be up):
    python3 run_capture.py --proxy http://capture-proxy:8081 \
        --shop http://shop.fwlab.test:9100 \
        --capture-file /logs/capture/capture.jsonl \
        --boundaries /logs/capture/boundaries.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import sys
import time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import benign_specs      # noqa: E402
import attack_specs      # noqa: E402
import drive_traffic     # noqa: E402
from send import send_spec  # noqa: E402

ENUMERABLE_FLOWS = [
    ("api-json", benign_specs.api_json),
    ("api-query", benign_specs.api_query),
    ("unseen-structure", benign_specs.unseen_structure),
    ("sqli", attack_specs.sqli),
    ("cmdi", attack_specs.cmdi),
    ("xss", attack_specs.xss),
    ("path-traversal", attack_specs.path_traversal),
    ("ssrf", attack_specs.ssrf),
]


def count_lines(path: str) -> int:
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for _ in f:
            n += 1
    return n


def wait_for_stable(path: str, settle: float, poll: float = 0.3, max_wait: float = 15.0) -> int:
    """Wait until the capture file stops growing (async browser sub-resources), then return
    the stable line count."""
    deadline = time.monotonic() + max_wait
    last = count_lines(path)
    time.sleep(settle)
    while time.monotonic() < deadline:
        now = count_lines(path)
        if now == last:
            return now
        last = now
        time.sleep(poll)
    return count_lines(path)


def check_proxy(proxy: str) -> None:
    u = urlparse(proxy)
    host, port = u.hostname, u.port or 8081
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"[ready] capture proxy {host}:{port} accepts connections", flush=True)
    except OSError as exc:
        raise SystemExit(f"[FAIL] capture proxy {proxy} not reachable: {exc}. "
                         "Bring up lab-app and capture-proxy first "
                         "(docker compose --profile extv1 up -d lab-app capture-proxy).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proxy", default="http://capture-proxy:8081")
    ap.add_argument("--shop", default="http://shop.fwlab.test:9100",
                    help="storefront base URL for the browser flows")
    ap.add_argument("--capture-file", default="/logs/capture/capture.jsonl")
    ap.add_argument("--boundaries", default="/logs/capture/boundaries.json")
    ap.add_argument("--settle", type=float, default=2.0,
                    help="seconds to wait for async browser sub-resources to flush")
    ap.add_argument("--only", default=None,
                    help="comma-separated flow names to run (default: all)")
    args = ap.parse_args(argv)

    check_proxy(args.proxy)

    only = set(args.only.split(",")) if args.only else None
    browser_flows = [
        ("browser-navigation", lambda: drive_traffic.browser_navigation(args.shop, args.proxy)),
        ("browser-forms-session", lambda: drive_traffic.browser_forms_session(args.shop, args.proxy)),
    ]

    boundaries = {"schema": "external-v1-capture-boundaries/1",
                  "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "capture_file": args.capture_file, "flows": []}

    def record_window(name, kind, group, expected, start, end):
        boundaries["flows"].append({
            "flow": name, "kind": kind, "group": group,
            "start": start, "end": end, "count": end - start,
            "expected": expected,
            "count_matches_expected": (expected is None or (end - start) == expected),
        })
        exp = "" if expected is None else f" (expected {expected})"
        flag = "" if (expected is None or end - start == expected) else "  <-- MISMATCH"
        print(f"[flow] {name:24s} captured {end - start}{exp}{flag}", flush=True)

    start_total = count_lines(args.capture_file)

    # browser flows first (longer, need settle)
    for name, run in browser_flows:
        if only and name not in only:
            continue
        start = wait_for_stable(args.capture_file, 0.2)
        run()
        end = wait_for_stable(args.capture_file, args.settle)
        record_window(name, "browser", name, None, start, end)

    # enumerable flows (one request per spec)
    for name, fn in ENUMERABLE_FLOWS:
        if only and name not in only:
            continue
        specs = fn()
        start = wait_for_stable(args.capture_file, 0.2)
        for spec in specs:
            send_spec(spec, args.proxy)
        end = wait_for_stable(args.capture_file, 0.5)
        record_window(name, "enumerable", name, len(specs), start, end)

    boundaries["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    boundaries["total_before"] = start_total
    boundaries["total_after"] = count_lines(args.capture_file)
    os.makedirs(os.path.dirname(args.boundaries) or ".", exist_ok=True)
    with open(args.boundaries, "w", encoding="utf-8") as f:
        json.dump(boundaries, f, indent=2, ensure_ascii=False)

    mism = [fl for fl in boundaries["flows"] if not fl["count_matches_expected"]]
    print(f"\ncapture done: {boundaries['total_after'] - start_total} record(s) this run")
    print(f"boundaries -> {args.boundaries}")
    if mism:
        print(f"WARNING: {len(mism)} enumerable flow(s) did not match expected counts; "
              "label_candidates.py will report them. This usually means a request was "
              "retried, redirected-and-followed, or a client error dropped one.")
    return 1 if mism else 0


if __name__ == "__main__":
    sys.exit(main())
