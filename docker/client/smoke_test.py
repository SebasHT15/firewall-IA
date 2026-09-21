"""firewall-IA Docker Lab — infrastructure smoke tests.

WHAT THIS IS
    A check that the four lab services are wired together correctly and that the
    gateway's three outcomes (ALLOW forwarded, BLOCK stopped, fail-closed stopped)
    survive containerization. It exercises plumbing.

WHAT THIS IS NOT
    Not External Test v1. Not an evaluation, not a benchmark, not a diagnostic.
    Three hand-written requests measure nothing about the model: no accuracy, no
    FPR, no FNR, no latency claim may be derived from this file's output. The
    fixtures below are infrastructure fixtures and are deliberately kept separate
    from any future external evaluation set (D37).

FIXTURE CHOICE, STATED PLAINLY
    The destination answers to the Docker network alias `app.fwlab.test`. That
    hostname is not arbitrary: `reports/diagnostics/real-http-fp-v1/` observed
    ordinary hostnames of this shape as ALLOW in every context it tested, while
    loopback hosts and the bare path `/` flipped to BLOCK. Using a hostname and
    path already known to be ALLOW keeps the ALLOW case measuring TRANSPORT rather
    than re-measuring the model. It is a deliberate choice, disclosed here.

    Headers are urllib's defaults. Nothing is added, removed or shaped to steer the
    model: every header is model input (ml_evaluation_methodology.md section 8), and
    tuning them would turn a plumbing check into an experiment.

    If the ALLOW fixture ever comes back 403, that is the model's decision on this
    input, not a broken lab. This script says so explicitly instead of hiding it.

USAGE
    python3 smoke_test.py <allow|block|failclosed|all>

    `failclosed` expects the control plane to be stopped by the caller; the host
    script docker/smoke_test.sh sequences that.
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

PROXY_URL = os.environ.get("LAB_PROXY_URL", "http://data-plane:8080")
DESTINATION = os.environ.get("LAB_DESTINATION", "app.fwlab.test:9000")
ACCESS_LOG = os.environ.get("ACCESS_LOG", "/logs/destination-access.jsonl")
READY_TIMEOUT = float(os.environ.get("LAB_READY_TIMEOUT", "60"))

# --- Fixtures -------------------------------------------------------------
# Benign. A static page fetch, the plainest request the lab can make.
ALLOW_URL = f"http://{DESTINATION}/index.html"
# Unambiguous SQL injection, the same shape as the manual verification already
# recorded in the README. SQL injection is an evaluable V4 category (recall
# 90.94% on the held-out split), so a BLOCK here is expected — but not guaranteed,
# and this script never treats one request as evidence about the model.
BLOCK_URL = f"http://{DESTINATION}/products.html?id=1%27%20OR%20%271%27%3D%271"


def log(msg: str) -> None:
    print(msg, flush=True)


def receipts() -> list[dict]:
    """Every request the destination has recorded, newest last."""
    try:
        with open(ACCESS_LOG, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def wait_for_proxy() -> None:
    """Block until the proxy accepts TCP connections, or give up loudly."""
    host, port = PROXY_URL.split("//", 1)[1].split(":")
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                log(f"[ready] proxy {host}:{port} accepts connections")
                return
        except OSError:
            time.sleep(1)
    raise SystemExit(f"[FAIL] proxy {host}:{port} not reachable after {READY_TIMEOUT:.0f}s")


def through_proxy(url: str) -> tuple[int, bytes]:
    """GET `url` using the data plane as an explicit HTTP proxy.

    Returns (status, body) for both success and HTTP error responses, because 403
    and 503 are the outcomes under test, not failures of the client.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": PROXY_URL})
    )
    try:
        with opener.open(url, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def case(name: str, url: str, expect_status: int, expect_receipt: bool) -> bool:
    """Run one case and report status plus whether the destination was reached."""
    before = len(receipts())
    log(f"\n[{name}] GET {url}")
    log(f"[{name}] via proxy {PROXY_URL}")
    try:
        status, body = through_proxy(url)
    except Exception as exc:                      # transport, not policy
        log(f"[{name}] FAIL transport error: {type(exc).__name__}: {exc}")
        return False
    after = receipts()
    new = after[before:]
    reached = len(new) > 0

    log(f"[{name}] status={status} (expected {expect_status})")
    log(f"[{name}] destination received {len(new)} new request(s) "
        f"(expected {'>=1' if expect_receipt else '0'})")
    for entry in new:
        log(f"[{name}]   receipt: {entry['method']} {entry['path']} "
            f"host={entry['host_header']}")
    if body:
        log(f"[{name}] body[:120]={body[:120]!r}")

    ok = (status == expect_status) and (reached == expect_receipt)
    if ok:
        log(f"[{name}] PASS")
    else:
        log(f"[{name}] FAIL")
        if status != expect_status and expect_status == 200 and status == 403:
            log(f"[{name}] NOTE: the gateway worked and returned the model's BLOCK. "
                f"The ALLOW fixture was classified BLOCK by V4. That is a model "
                f"decision on this input, not a lab defect, and it is not an FPR.")
    return ok


def case_allow() -> bool:
    return case("ALLOW", ALLOW_URL, expect_status=200, expect_receipt=True)


def case_block() -> bool:
    return case("BLOCK", BLOCK_URL, expect_status=403, expect_receipt=False)


def case_failclosed() -> bool:
    log("\n[FAILCLOSED] the control plane must be stopped by the caller "
        "(docker compose stop control-plane)")
    return case("FAILCLOSED", ALLOW_URL, expect_status=503, expect_receipt=False)


PHASES = {
    "allow": [case_allow],
    "block": [case_block],
    "failclosed": [case_failclosed],
    "all": [case_allow, case_block],          # fail-closed needs host sequencing
}


def main(argv: list[str]) -> int:
    phase = argv[1] if len(argv) > 1 else "all"
    if phase not in PHASES:
        log(f"usage: smoke_test.py <{'|'.join(PHASES)}>")
        return 2

    log("firewall-IA Docker Lab — INFRASTRUCTURE SMOKE TEST")
    log("not an evaluation, not a benchmark, no model metric may be derived from it")
    log(f"proxy={PROXY_URL} destination={DESTINATION} access_log={ACCESS_LOG}")
    wait_for_proxy()

    results = [(fn.__name__, fn()) for fn in PHASES[phase]]
    log("\n--- summary ---")
    for name, ok in results:
        log(f"{'PASS' if ok else 'FAIL'}  {name}")
    failed = [n for n, ok in results if not ok]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
