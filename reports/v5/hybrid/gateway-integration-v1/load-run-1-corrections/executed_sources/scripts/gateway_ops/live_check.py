"""
Live verification of the cascade gateway: real mitmdump, addon, canonical workers, egress guard and
Model 2 worker (CPU), an independent sink process, and V4/V5 doubles.

    .venv-dataplane/bin/python scripts/gateway_ops/live_check.py --out <dir> [--group NAME ...]

Real services: `real_check.py`. Isolated measurement: `real_perf.py`.

THIS PROVES MECHANISM, NOT DETECTION. The V4 and V5 answers are a fixed rule. L1 below
compares a reference label with that rule, so it validates the plumbing of the L1/L2/L3 accounting
and says nothing about model quality (D41). A request delivered to the inert sink is delivery only:
this harness cannot observe, and never reports, whether an attack would have succeeded.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import fast_path as fp             # noqa: E402
import live_stack as L             # noqa: E402
import make_dev_manifest as MM     # noqa: E402

POLICY = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies/fast_path_lab_app.json")
MUTATE_ADDON = os.path.join(HERE, "fixtures", "after_hook_mutation_addon.py")

HOST = b"Host: shop.local\r\n"
BENIGN = b"GET /catalog/widgets HTTP/1.1\r\n" + HOST + b"\r\n"
EVIL = b"GET /search?q=evil HTTP/1.1\r\n" + HOST + b"\r\n"
TRAVERSAL = b"GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: f.local\r\n\r\n"
HEALTHZ = b"GET /healthz HTTP/1.1\r\nHost: lab.local\r\n\r\n"
POST_HEAD = b"POST /api/items HTTP/1.1\r\n" + HOST + b"Content-Type: application/json\r\n"


SENTINELS = (b"PrivQueryZq7", b"PrivHeaderZq7", b"PrivBodyZq7", b"q=evil", b"etc%2fpasswd")
PRIVACY_REQUESTS = (
    b"POST /s?token=PrivQueryZq7 HTTP/1.1\r\nHost: shop.local\r\nX-Secret: PrivHeaderZq7\r\n"
    b"Content-Type: text/plain\r\nContent-Length: 11\r\n\r\nPrivBodyZq7",
    b"POST /s?token=PrivQueryZq7 HTTP/1.1\r\nHost: shop.local\r\nX-Secret: PrivHeaderZq7\r\n"
    b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nab",
    b"GET /s?token=PrivQueryZq7 HTTP/1.1\r\nHost: shop.local\r\nTransfer-Encoding: PrivHeaderZq7\r\n\r\n",
    b"GET /s?token=PrivQueryZq7 HTTP/9.9\r\nHost: shop.local\r\n\r\n",
)


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, group, check, passed, **observed):
        self.rows.append({"group": group, "check": check, "passed": bool(passed),
                          "observed": observed})
        print(f"[{'PASS' if passed else 'FAIL'}] {group}: {check} {observed if not passed else ''}",
              flush=True)


def wait_records(stack, predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = [r for r in stack.records() if predicate(r)]
        if rows:
            return rows
        time.sleep(0.02)
    return []


def wire_sha(raw):
    return hashlib.sha256(raw).hexdigest()


def received(stack, count_before):
    time.sleep(0.05)
    return stack.sink_records()[count_before:]


def last_decision(stack, seen):
    rows = wait_records(stack, lambda r: r.get("kind") == "decision", 0.5)
    fresh = rows[seen:]
    return fresh[-1] if fresh else None


def case(stack, checks, group, name, segments, *, status, delivered, stage=None, responses=1,
         reference=None, levels=None):
    """Send one case and check the client status and the independent reception. Records the L levels
    when a reference label is given. Returns (statuses, sink rows, decision record)."""
    sink_before = len(stack.sink_records())
    decisions_before = len([r for r in stack.records() if r.get("kind") == "decision"])
    calls_before = stack.calls("v5")
    statuses = stack.send(segments, responses=responses)
    rows = received(stack, sink_before)
    decision = last_decision(stack, decisions_before)
    actual_stage = decision.get("deciding_stage") if decision else "before_addon"
    ok = (statuses == status if isinstance(status, list) else statuses[0] in
          (status if isinstance(status, tuple) else (status,)))
    ok = ok and (len(rows) == delivered)
    if stage is not None:
        ok = ok and actual_stage == stage
    binding_ok = True
    if decision and decision.get("applied") == "FORWARD" and decision.get("wire_sha256") and rows:
        binding_ok = rows[-1]["wire_sha256"] == decision["wire_sha256"]
    checks.add(group, name, ok and binding_ok, statuses=statuses, delivered=len(rows),
               stage=actual_stage, reason=decision.get("reason") if decision else None,
               decided_equals_delivered=binding_ok, v5_calls=stack.calls("v5") - calls_before
               if calls_before is not None else None)
    if levels is not None and reference is not None:
        levels.append(l_levels(name, reference, decision, statuses[0], len(rows) > 0))
    return statuses, rows, decision


def l_levels(name, reference, decision, http_status, delivered,
             reference_kind="harness_expectation"):
    """D41, in neutral terms. L1: reference vs decision. L2: decision vs observed behavior (status and
    independent reception). L3: reference vs delivery. A reference is an expectation, not proof: it
    is never called an attack here, and a delivered request is never called an exploit."""
    applied = decision.get("applied") if decision else "DENY"
    decided = "ALLOW" if applied == "FORWARD" else "BLOCK"
    l2_ok = (applied == "FORWARD" and http_status == 200 and delivered) or \
            (applied == "DENY" and http_status != 200 and not delivered)
    if reference == "BLOCK":
        l3 = "reference_block_not_delivered" if not delivered else "reference_block_delivered"
    else:
        l3 = "reference_allow_delivered" if delivered else "reference_allow_not_delivered"
    return {"case": name, "reference": reference, "reference_kind": reference_kind,
            "L1_decision": decided, "L1_agrees_with_reference": decided == reference,
            "L2_conformant": bool(l2_ok), "L3_outcome": l3,
            "deciding_stage": (decision or {}).get("deciding_stage", "before_addon")}


def group_framing(args, checks, levels):
    """CASCADE_ACTIVE scope, ambiguity, segmentation and decided==delivered, with the real Model 2."""
    group = "framing"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE", fast_path=True)
    stack.start()
    try:
        stack.wait_ready()
        c = lambda *a, **k: case(stack, checks, group, *a, **k)  # noqa: E731
        c("benign GET delivered", [BENIGN], status=200, delivered=1, stage="v5",
          reference="ALLOW", levels=levels)
        c("V5 block not delivered", [EVIL], status=403, delivered=0, stage="v5",
          reference="BLOCK", levels=levels)
        c("real Model 2 early block, no V5 call", [TRAVERSAL], status=403, delivered=0,
          stage="model2", reference="BLOCK", levels=levels)
        c("Fast Path fixture applied, no model call", [HEALTHZ], status=200, delivered=1,
          stage="fast_path", reference="ALLOW", levels=levels)

        body = b'{"a":1}'
        message = POST_HEAD + b"Content-Length: 7\r\n\r\n" + body
        c("Content-Length request split every 5 bytes",
          [message[i:i + 5] for i in range(0, len(message), 5)], status=200, delivered=1, stage="v5")
        c("split inside CRLF of the head", [BENIGN[:-3], BENIGN[-3:-1], BENIGN[-1:]], status=200,
          delivered=1, stage="v5")
        chunked = (POST_HEAD + b"Transfer-Encoding: chunked\r\n\r\n"
                   b"3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n")
        _, rows, decision = c("chunked request, segments across chunk boundaries",
                              [chunked[:60], chunked[60:80], chunked[80:90], chunked[90:]],
                              status=200, delivered=1, stage="v5")
        checks.add(group, "chunked delivered as what was decided",
                   rows and decision and rows[-1]["wire_sha256"] == decision.get("wire_sha256"))
        c("evil split across segments is decided on the whole request",
          [EVIL[:17], EVIL[17:21], EVIL[21:]], status=403, delivered=0, stage="v5",
          reference="BLOCK", levels=levels)
        c("body carrying a whole request is one message, decided with its body",
          [POST_HEAD + b"Content-Length: %d\r\n\r\n" % len(EVIL) + EVIL], status=403, delivered=0,
          stage="v5", reference="BLOCK", levels=levels)
        c("two pipelined requests: benign delivered, evil not",
          [BENIGN + EVIL], status=[200, 403], delivered=1, responses=2)

        expect = POST_HEAD + b"Content-Length: 7\r\nExpect: 100-continue\r\n\r\n"
        c("Expect: 100-continue, body after the interim response", [expect, body],
          status=[100, 200], delivered=1, responses=2, stage="v5")
        c("two Host headers are ambiguous", [b"GET /a HTTP/1.1\r\n" + HOST + b"Host: other.local\r\n\r\n"],
          status=400, delivered=0, stage="framing")

        rejected = (400, 403, 501, 502, 505)
        c("TE and CL together", [POST_HEAD + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                                 b"\r\n0\r\n\r\n"], status=rejected, delivered=0)
        c("duplicate Content-Length", [POST_HEAD + b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nab"],
          status=rejected, delivered=0)
        c("obfuscated Transfer-Encoding", [POST_HEAD + b"Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"],
          status=rejected, delivered=0)
        c("obsolete line folding refused by the strict parser",
          [b"GET /a HTTP/1.1\r\n" + HOST + b"X-Fold: a\r\n b\r\n\r\n"], status=rejected, delivered=0)
        _, rows, decision = c("bare-LF request is decided and delivered in its normalized form",
                              [b"GET /catalog/widgets HTTP/1.1\nHost: shop.local\n\n"], status=200,
                              delivered=1, stage="v5")
        c("bare LF cannot hide a TE header behind a value",
          [POST_HEAD + b"Content-Length: 5\r\nX: a\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"],
          status=rejected, delivered=0)
        c("HTTP/1.0 outside the scope", [b"GET /a HTTP/1.0\r\n" + HOST + b"\r\n"], status=505,
          delivered=0, stage="framing")
        c("absolute-form outside the scope", [b"GET http://shop.local/a HTTP/1.1\r\n" + HOST + b"\r\n"],
          status=(501, 400), delivered=0)
        c("asterisk-form outside the scope", [b"OPTIONS * HTTP/1.1\r\n" + HOST + b"\r\n"], status=501,
          delivered=0, stage="framing")
        c("WebSocket upgrade outside the scope",
          [b"GET /ws HTTP/1.1\r\n" + HOST + b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
           b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"],
          status=501, delivered=0, stage="framing")
        c("h2c upgrade header is stripped by mitmproxy before the decision, delivered as decided",
          [b"GET /a HTTP/1.1\r\n" + HOST + b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
           b"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"], status=200, delivered=1, stage="v5")
        statuses = stack.send([b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"], timeout=3.0)
        checks.add(group, "HTTP/2 prior knowledge never delivered",
                   statuses[0] != 200 and not received(stack, len(stack.sink_records())),
                   statuses=statuses)
        client_hello = bytes.fromhex("16030100310100002d0303") + b"\x00" * 32 + \
            bytes.fromhex("00000200350100000400000000")
        before = len(stack.sink_records())
        try:
            statuses = stack.send([client_hello], timeout=2.0)
        except OSError:
            statuses = [None]
        checks.add(group, "TLS on the cleartext listener never delivered",
                   statuses[0] != 200 and len(stack.sink_records()) == before, statuses=statuses)
        c("body over the mitmproxy limit", [POST_HEAD + b"Content-Length: 70000\r\n\r\n" + b"a" * 70000],
          status=(413, None), delivered=0)
        big = b"a" * 30000
        c("body over the received-body bound is refused before canonicalization",
          [POST_HEAD + b"Content-Length: %d\r\n\r\n" % len(big) + big], status=413, delivered=0,
          stage="canonical")
        big = b"a" * 19500
        c("text over the token budget is rejected, never truncated",
          [b"POST /" + b"p" * 1000 + b" HTTP/1.1\r\n" + HOST
           + b"Content-Type: application/x-www-form-urlencoded\r\n"
           + b"Content-Length: %d\r\n\r\n" % len(big) + big], status=400, delivered=0, stage="protocol")

        # Reaching the guard without a decision.
        before = len(stack.sink_records())
        statuses = stack.send([BENIGN], port=stack.guard_port, timeout=2.0)
        checks.add(group, "direct connection to the guard is refused, nothing delivered",
                   statuses == [502] and len(received(stack, before)) == 0, statuses=statuses)
        status_doc = stack.status()
        checks.add(group, "no ticket left behind", status_doc["tickets"] == 0, tickets=status_doc["tickets"])
        metrics = stack.metrics()
        checks.add(group, "guard rejection counted",
                   'firewall_egress_total{event="REJECTED",reason="unticketed"}' in metrics)
        for raw in PRIVACY_REQUESTS:
            stack.send([raw], timeout=2.0)
        time.sleep(0.3)
        privacy_hit = _privacy_scan(stack)
        checks.add(group, "records and gateway log carry no target, query or body",
                   not privacy_hit, hits=privacy_hit)
    finally:
        stack.stop()


def _privacy_scan(stack):
    """Sentinel strings sent in a query, a header value and a body, valid and malformed, must not
    appear in any file the gateway persists: records, stdout log, or the V4 path's log lines."""
    hits = []
    for name in ("decisions.jsonl", "gateway.log"):
        path = os.path.join(stack.workdir, name)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                data = fh.read()
            hits += [f"{name}:{s.decode()}" for s in SENTINELS if s in data]
    return hits


def group_after_hook_mutation(args, checks, levels):
    """A later addon changes the request after the decision: the guard must refuse those bytes."""
    group = "after_hook_mutation"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE", mitmdump_extra=("-s", MUTATE_ADDON))
    stack.start()
    try:
        stack.wait_ready()
        before = len(stack.sink_records())
        statuses = stack.send([BENIGN])
        checks.add(group, "changed after the decision: not delivered, 502",
                   statuses == [502] and not received(stack, before), statuses=statuses)
        rows = wait_records(stack, lambda r: r.get("event") == "REJECTED")
        checks.add(group, "guard recorded the mismatch",
                   rows and rows[-1].get("reason") == "unticketed")
    finally:
        stack.stop()


def group_v5_failures(args, checks, levels):
    """V5 invalid/error/timeout deny; Model 2 failure defers; contract drift stops readiness."""
    group = "failures"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE")
    stack.start()
    try:
        stack.wait_ready()
        for behavior, name in (("invalid", "V5 invalid output"), ("error500", "V5 HTTP 500"),
                               ("saturated503", "V5 saturated 503"), ("bad_json", "V5 malformed reply"),
                               ("hang", "V5 timeout")):
            stack.control("v5", behavior)
            case(stack, checks, group, f"{name} denies, nothing delivered", [BENIGN], status=503,
                 delivered=0, stage="v5")
        stack.control("v5", "normal")
        case(stack, checks, group, "V5 recovered: benign delivered again", [BENIGN], status=200,
             delivered=1, stage="v5")

        _kill_model2(stack)
        _, _, decision = case(stack, checks, group, "Model 2 worker killed: request defers to V5",
                              [BENIGN], status=200, delivered=1, stage="v5")
        checks.add(group, "Model 2 failure recorded as non-OK, V5 decided",
                   decision and (decision.get("model2") or {}).get("status") == "error",
                   model2=(decision or {}).get("model2"))
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and stack.status()["model2_worker"]["state"] != "READY":
            time.sleep(0.05)
        _, _, decision = case(stack, checks, group, "Model 2 worker restarted: early block is back",
                              [TRAVERSAL], status=403, delivered=0, stage="model2")

        stack.control("v5", "contract_mismatch")
        detail = stack.wait_ready(want=False, timeout=5.0)
        checks.add(group, "V5 serving another recipe stops readiness",
                   "v5_recipe_sha256_mismatch" in detail["cascade_problems"], detail=detail)
        case(stack, checks, group, "not ready: fail-closed, nothing delivered", [BENIGN], status=503,
             delivered=0, stage="readiness")
        stack.control("v5", "normal")
        stack.wait_ready(timeout=5.0)
        case(stack, checks, group, "contract restored: serving again", [BENIGN], status=200,
             delivered=1, stage="v5")
    finally:
        stack.stop()


def _kill_model2(stack):
    for pid in _model2_pids(stack):
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


def _model2_pids(stack):
    """Model 2 workers started by this stack's gateway (their parent is the gateway process)."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmd = fh.read()
            with open(f"/proc/{entry}/stat", encoding="latin-1") as fh:
                parent = int(fh.read().rsplit(")", 1)[1].split()[1])
        except OSError:
            continue
        if b"model2_worker.py" in cmd and parent == stack.gateway_proc.pid:
            pids.append(int(entry))
    return pids


def group_rollback(args, checks, levels):
    """Return to V4 without a restart, with V5 down."""
    group = "return_to_v4"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE")
    stack.start()
    try:
        stack.wait_ready()
        case(stack, checks, group, "ACTIVE decides", [BENIGN], status=200, delivered=1, stage="v5")
        v4_before = stack.calls("v4")
        stack.rollback(True)
        stack.control("v5", "error500")
        before = len(stack.sink_records())
        v5_before = stack.calls("v5")
        statuses = stack.send([BENIGN])
        checks.add(group, "sentinel: V4 decides and the request is delivered through the guard",
                   statuses == [200] and len(received(stack, before)) == 1
                   and stack.calls("v4") == v4_before + 1 and stack.calls("v5") == v5_before,
                   statuses=statuses, status=stack.status()["effective_mode"])
        before = len(stack.sink_records())
        statuses = stack.send([EVIL])
        checks.add(group, "V4 block applied during the return",
                   statuses == [403] and not received(stack, before), statuses=statuses)
        ready, body = stack.admin("/readyz")
        checks.add(group, "readiness follows V4 during the return", ready == 200, body=body[:200].decode())
        stack.control("v4", "error500")
        before = len(stack.sink_records())
        statuses = stack.send([BENIGN])
        checks.add(group, "V4 failing during the return stays fail-closed",
                   statuses == [503] and not received(stack, before), statuses=statuses)
        stack.control("v4", "normal")
        stack.control("v5", "normal")
        stack.rollback(False)
        stack.wait_ready(timeout=5.0)
        case(stack, checks, group, "sentinel removed: ACTIVE decides again", [BENIGN], status=200,
             delivered=1, stage="v5")
    finally:
        stack.stop()

    # Return to V4 by configuration: restart with mode V4_ONLY.
    stack = make_stack(args, "return_to_v4_restart", mode="V4_ONLY")
    stack.start()
    try:
        time.sleep(0.5)
        before = len(stack.sink_records())
        statuses = stack.send([BENIGN]) + stack.send([EVIL])
        checks.add(group, "restart with V4_ONLY: V4 decides, no V5 call, no cascade runtime",
                   statuses == [200, 403] and len(received(stack, before)) == 1
                   and stack.calls("v5") == 0 and stack.calls("v4") == 2
                   and stack.admin("/readyz")[0] is None, statuses=statuses)
    finally:
        stack.stop()


def group_observe(args, checks, levels):
    """V4 keeps authority; the cascade is recorded; its failures change nothing."""
    group = "observe"
    stack = make_stack(args, group, mode="CASCADE_OBSERVE", fast_path=True)
    stack.start()
    try:
        stack.wait_ready(require_cascade=True)
        expected = [(BENIGN, 200), (EVIL, 403), (TRAVERSAL, 200), (HEALTHZ, 200)]
        for behavior in ("normal", "error500", "hang", "invalid"):
            stack.control("v5", behavior)
            for raw, status in expected:
                before = len(stack.sink_records())
                statuses = stack.send([raw], timeout=4.0)
                got = len(received(stack, before))
                checks.add(group, f"V4 action unchanged with V5 {behavior}: {raw[:24]!r}",
                           statuses == [status] and got == (1 if status == 200 else 0),
                           statuses=statuses, delivered=got)
        stack.control("v5", "normal")
        rows = wait_records(stack, lambda r: r.get("observation") == "computed", 3.0)
        disagreement = [r for r in rows if r.get("cascade_stage") == "model2"]
        checks.add(group, "cascade recorded beside V4 (real Model 2 would block what V4 double allows)",
                   disagreement and disagreement[0]["applied"] == "FORWARD"
                   and disagreement[0]["cascade_applied"] == "DENY",
                   computed=len(rows))
        fast = [r for r in rows if r.get("cascade_stage") == "fast_path"]
        checks.add(group, "hypothetical FAST_ALLOW recorded, not applied", bool(fast))
        audits = wait_records(stack, lambda r: r.get("kind") == "fast_path_audit")
        checks.add(group, "hypothetical permit audited as not applied",
                   audits and all(r["applied"] is False for r in audits), audits=len(audits))
        _kill_model2(stack)
        before = len(stack.sink_records())
        statuses = stack.send([BENIGN])
        checks.add(group, "Model 2 worker killed: V4 action unchanged",
                   statuses == [200] and len(received(stack, before)) == 1, statuses=statuses)
        checks.add(group, "direct path: the guard is not listening in OBSERVE",
                   not stack.status()["egress_guard"])
    finally:
        stack.stop()

    # A manifest that cannot be used disables the observation, never V4.
    stack = make_stack(args, "observe_bad_manifest", mode="CASCADE_OBSERVE", broken_manifest=True)
    stack.start()
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and stack.admin("/readyz")[0] != 200:
            time.sleep(0.05)
        ready, body = stack.admin("/readyz")
        statuses = stack.send([BENIGN]) + stack.send([EVIL])
        checks.add(group, "unusable manifest: observation off and reported, V4 serves",
                   statuses == [200, 403] and b"manifest_unusable" in body
                   and stack.calls("v5") == 0, statuses=statuses, ready=ready, body=body[:300].decode())
    finally:
        stack.stop()


def group_v5_only(args, checks, levels):
    group = "v5_only"
    stack = make_stack(args, group, mode="V5_ONLY", fast_path=False)
    stack.start()
    try:
        stack.wait_ready()
        case(stack, checks, group, "V5 allows", [BENIGN], status=200, delivered=1, stage="v5",
             reference="ALLOW", levels=levels)
        case(stack, checks, group, "V5 blocks", [EVIL], status=403, delivered=0, stage="v5",
             reference="BLOCK", levels=levels)
        _, _, decision = case(stack, checks, group, "no Model 2 stage: V5 decides the traversal too",
                              [TRAVERSAL], status=200, delivered=1, stage="v5", reference="BLOCK",
                              levels=levels)
        checks.add(group, "Model 2 and Fast Path not consulted",
                   decision and decision.get("model2") is None and decision.get("fast_path") is None)
        stack.control("v5", "invalid")
        case(stack, checks, group, "V5 invalid denies", [BENIGN], status=503, delivered=0, stage="v5")
    finally:
        stack.stop()


def group_audit(args, checks, levels):
    group = "fast_path_audit"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE", fast_path=True)
    stack.start()
    try:
        stack.wait_ready()
        case(stack, checks, group, "permit applied", [HEALTHZ], status=200, delivered=1,
             stage="fast_path")
        rows = wait_records(stack, lambda r: r.get("kind") == "fast_path_audit")
        checks.add(group, "sampled permit audited, V5 agrees",
                   rows and rows[-1]["verdict"] == "AGREE" and rows[-1]["applied"] is True,
                   rows=rows[-1:] if rows else None)
        stack.control("v5", "block_all")
        calls_before = stack.calls("v5")
        _, sink_rows, _ = case(stack, checks, group, "auditor says BLOCK: the permit stays applied",
                               [HEALTHZ], status=200, delivered=1, stage="fast_path")
        rows = wait_records(stack, lambda r: r.get("verdict") == "DISAGREE")
        checks.add(group, "disagreement recorded, no retroactive effect",
                   rows and rows[-1]["retroactive_effect"] == "none"
                   and stack.calls("v5") == calls_before + 1, rows=rows[-1:] if rows else None)
        case(stack, checks, group, "the next permit is still decided by the policy", [HEALTHZ],
             status=200, delivered=1, stage="fast_path")
        stack.control("v5", "hang")
        case(stack, checks, group, "auditor timeout never delays or denies the permit", [HEALTHZ],
             status=200, delivered=1, stage="fast_path")
        rows = wait_records(stack, lambda r: r.get("status") == "TIMEOUT", 4.0)
        checks.add(group, "audit timeout recorded", bool(rows))
    finally:
        stack.stop()
    metrics_rows = [r for r in stack.records() if r.get("kind") == "fast_path_audit"]
    checks.add(group, "every permit ended in exactly one audit record",
               len(metrics_rows) == 4, rows=len(metrics_rows))


def group_shutdown(args, checks, levels):
    group = "shutdown"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE")
    stack.start()
    try:
        stack.wait_ready()
        case(stack, checks, group, "serving before shutdown", [BENIGN], status=200, delivered=1)
        code = stack.stop_gateway()
        checks.add(group, "clean exit on SIGTERM", code == 0, code=code)
        leftovers = _model2_pids(stack)
        checks.add(group, "no worker left behind", not leftovers, leftovers=leftovers)
    finally:
        stack.stop()
    # Refused start.
    stack = make_stack(args, "refused_start", mode="CASCADE_ACTIVE", broken_manifest=True)
    stack.start_sink()
    stack.start_doubles()
    stack.start_gateway()
    code = stack.gateway_proc.wait(timeout=15)
    checks.add(group, "unusable manifest in an authoritative mode: the gateway does not run",
               code not in (0, None), code=code)
    stack.stop()


def group_saturation(args, checks, levels):
    """A short burst against small admission bounds. Not a capacity or latency measurement."""
    group = "saturation"
    stack = make_stack(args, group, mode="CASCADE_ACTIVE", max_inflight=1, max_waiting=1)
    stack.start()
    try:
        stack.wait_ready()
        stack.control("v5", "slow")
        with concurrent.futures.ThreadPoolExecutor(12) as pool:
            statuses = list(pool.map(lambda _: stack.send([BENIGN], timeout=6.0)[0], range(12)))
        stack.control("v5", "normal")
        delivered = len(received(stack, 0))
        served, refused = statuses.count(200), statuses.count(503)
        checks.add(group, "burst over the bounds: every request answered, excess fail-closed",
                   served + refused == 12 and refused > 0 and delivered == served,
                   served=served, refused=refused, delivered=delivered)
        metrics = stack.metrics()
        checks.add(group, "saturation counted", 'firewall_admission_total{result="saturated"}' in metrics)
        case(stack, checks, group, "recovers after the burst", [BENIGN], status=200, delivered=1,
             stage="v5")
    finally:
        stack.stop()


GROUPS = {"framing": group_framing, "after_hook_mutation": group_after_hook_mutation,
          "failures": group_v5_failures, "return_to_v4": group_rollback, "observe": group_observe,
          "v5_only": group_v5_only, "fast_path_audit": group_audit, "shutdown": group_shutdown,
          "saturation": group_saturation}


def make_stack(args, name, *, mode, fast_path=False, mitmdump_extra=(), broken_manifest=False,
               v5_timeout=None, max_inflight=None, max_waiting=None, overrides=None,
               manifest=None):
    workdir = os.path.join(args.work, name)
    if os.path.exists(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir)
    manifest = manifest or args.manifest
    if broken_manifest:
        manifest = os.path.join(workdir, "broken_manifest.json")
        with open(args.manifest, encoding="utf-8") as fh:
            document = json.load(fh)
        document["model2"]["artifact_sha256"] = "0" * 64
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
    overrides = dict(overrides or {})
    if fast_path:
        overrides.update(fast_path_policy=POLICY, fast_path_sha256=fp.load_policy(POLICY).sha256)
    if v5_timeout:
        overrides["v5_timeout"] = v5_timeout
    if max_inflight:
        overrides.update(max_inflight=max_inflight, max_waiting=max_waiting)
    return L.Stack(workdir, mode=mode, manifest=manifest, v5_url=args.v5_url, v4_url=args.v4_url,
                   config_overrides=overrides, mitmdump_extra=mitmdump_extra)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", help="process logs and records (default: <out>/work)")
    parser.add_argument("--manifest", help="default: a fresh development fixture")
    parser.add_argument("--group", action="append", choices=tuple(GROUPS))
    args = parser.parse_args()
    args.v5_url = args.v4_url = None
    os.makedirs(args.out, exist_ok=True)
    args.work = args.work or os.path.join(args.out, "work")
    os.makedirs(args.work, exist_ok=True)
    if not args.manifest:
        args.manifest = os.path.join(args.work, "dev_manifest.json")
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump(MM.build("baseline34"), fh, indent=2, sort_keys=True)

    checks, levels = Checks(), []
    selected = args.group or list(GROUPS)
    started = time.time()
    for name in selected:
        print(f"=== {name}", flush=True)
        try:
            GROUPS[name](args, checks, levels)
        except Exception as exc:  # noqa: BLE001 — a group that dies is a failed check, not a skip
            checks.add(name, "group completed", False, error=f"{type(exc).__name__}: {exc}")
    failed = [c for c in checks.rows if not c["passed"]]
    result = {
        "schema": "firewall-gateway-live-check/v1", "scope": "DOUBLES: V4/V5 answers are a fixed "
        "rule; mechanism evidence, not detection evidence",
        "v5_real": False, "v4_real": False, "started_utc": started,
        "duration_s": time.time() - started, "groups": selected, "checks": checks.rows,
        "total": len(checks.rows), "passed": len(checks.rows) - len(failed), "failed": len(failed),
        "L_levels": levels,
        "L_levels_note": "With doubles, L1 compares an expectation with a fixed rule (and the real "
                         "Model 2 on CPU), so it validates accounting, not quality. A reference is "
                         "not a confirmed attack; L3 delivery to an inert sink is not exploitation."}
    with open(os.path.join(args.out, "live_check.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"TOTAL {result['passed']}/{result['total']} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
